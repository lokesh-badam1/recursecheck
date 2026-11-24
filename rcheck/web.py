"""RecurseCheck web UI: pick a lab resolver, choose the query rate and vantage point, see the verdict.

    python -m rcheck.web --host 0.0.0.0 --port 8080

Safety: the browser can only send a target NAME, one of two fixed vantage points (external/internal),
a rate of 1-10 queries per second (always sent within 1 second). The server looks the name up in the
allow-list (targets.yaml); free-text IPs are never accepted, so the scope guard cannot be bypassed.
One test runs at a time. Every query still goes through the token-bucket rate controller (set to the
chosen rate, never above MAX_RATE), the audit log and the classifier.

A test is a background job: POST /api/test starts it, GET /api/job/<id> returns live counters
(queries sent, replies received, names seen by the decoy server) and, once finished, the verdict.
"""
import argparse
import json
import pathlib
import random
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import config
from .audit import Audit
from .classifier import categorize_decoy, classify_explained
from .decoylog import DecoyLog
from .guard import ScopeGuard
from .naive import naive_classify
from .probe import Prober
from .rate import MAX_RATE, RateController

INDEX = pathlib.Path(__file__).with_name("web_index.html")
MAX_SECONDS = 1  # every test is a one-second burst
COOLDOWN = 0.5  # pause after the baseline so a resolver-side limit starts each test with a full allowance

ANSWERS = {
    "Recursive": ("YES", "Recursion is allowed",
                  "This server performed a real recursive lookup for this client: it is an open resolver."),
    "Refused": ("NO", "Recursion is not offered to this client",
                "The server explicitly refuses queries from this client (an access policy is in place)."),
    "Authoritative-only": ("NO", "Recursion is not offered",
                           "The server answers only for its own zone and does not perform lookups for others."),
    "Inconclusive": ("UNKNOWN", "Could not be determined",
                     "The evidence is not enough for a safe conclusion. See the reason below."),
}


def expected_for(target, vantage):
    """Ground truth depends on where the query comes from.

    Policy-refusing servers recurse for clients inside the allowed range, so an internal probe
    should find them Recursive; every other lab server behaves the same from both vantage points.
    """
    exp = target.get("expected")
    if vantage == "internal" and target.get("type") == "refusing":
        return "Recursive"
    return exp


def accepted_for(target, vantage):
    """Labels that count as correct. A lossy open server is Inconclusive in the strict scored run, but when one
    proven reply is enough it may also be (correctly) called Recursive, so both are accepted."""
    exp = expected_for(target, vantage)
    if target.get("type") == "lossy":
        return {exp, "Recursive"}
    return {exp}


def explain(label, vantage):
    answer, headline, detail = ANSWERS[label]
    if vantage == "internal" and label == "Recursive":
        detail = ("Recursion works for a client inside the allowed network. This does not show that outsiders "
                  "can use it: switch the toggle to External to check that.")
    elif vantage == "internal" and label == "Refused":
        headline = "Recursion is refused even for an internal client"
        detail = "The server refuses this internal client too, so the policy does not cover this source address."
    return answer, headline, detail


def summarize(ev):
    if ev is None:
        return None
    return {
        "phase": ev.get("phase"), "qname": ev.get("qname"), "status": ev.get("status"),
        "rcode": ev.get("rcode"), "ra": ev.get("ra"), "aa": ev.get("aa"),
        "answer": ", ".join(ev.get("answers", [])) or None, "seen": ev.get("seen"),
        "rtt_ms": ev.get("rtt_ms"),
    }


class Job:
    """One test of one resolver: a baseline query, then qps x seconds decoy queries, each with its own unique name."""

    def __init__(self, app, name, vantage, qps, seconds, stop_early):
        self.app, self.name, self.vantage = app, name, vantage
        self.qps, self.seconds, self.stop_early = qps, seconds, stop_early
        self.id = uuid.uuid4().hex[:8]
        self.target = app.targets[name]
        self.source = app.vantages[vantage]["source"]
        self.planned = qps * seconds
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.state, self.error, self.result = "running", None, None
        self.baseline = None
        self.early = None            # index of the first proven query
        self.slots = [{"state": "pending"} for _ in range(self.planned)]
        self.events = [None] * self.planned
        self.names = {}
        self.sent = self.replies = self.seen = 0
        self.t0 = None
        self.started = time.monotonic()
        self.finished = None

    # ---- live counters, called by the prober from the query threads ----
    def _hook(self, kind, ev):
        if ev.get("phase") != "decoy":
            return
        i = self.names.get(ev.get("qname"))
        if i is None:
            return
        with self.lock:
            s = self.slots[i]
            if kind == "sent":
                s.update(state="sent", t=round(time.monotonic() - self.t0, 2))
                self.sent += 1
                return
            ok = ev.get("status") == "OK"
            s.update(state="reply" if ok else "noreply", rcode=ev.get("rcode") if ok else ev.get("status"),
                     ra=ev.get("ra"), aa=ev.get("aa"), answer=", ".join(ev.get("answers", [])) or None,
                     seen=bool(ev.get("seen")), rtt_ms=ev.get("rtt_ms"))
            self.replies += 1 if ok else 0
            self.seen += 1 if ev.get("seen") else 0
            if categorize_decoy(ev) == "RECURSIVE":
                s["proof"] = True
                if self.early is None:
                    self.early = i
                    if self.stop_early:
                        self.stop.set()  # stop sending: recursion is already proven

    def _one(self, i, label):
        ev = self.prober.query(self.target["ip"], f"{label}.{self.app.zone}", "A", "decoy",
                               label=label, source=self.source)
        self.events[i] = ev

    def run(self):
        app = self.app
        try:
            app.check_source(self.source)
            if not app.decoy.exists():
                raise RuntimeError("decoy log not found; is the lab running?")
            app.decoy.mark()
            seed = int(time.time() * 1000) & 0xFFFFFFFF
            rng = random.Random(seed)
            labels = []
            while len(labels) < self.planned:  # every query gets a different name
                lab = "rc" + format(rng.getrandbits(40), "010x")
                if lab not in labels:
                    labels.append(lab)
            self.names = {f"{lab}.{app.zone}": i for i, lab in enumerate(labels)}
            self.prober = Prober(app.guard, RateController(self.qps, self.qps), app.audit, self.stop, app.decoy,
                                 app.marker, app.timeout, retries=0, hook=self._hook,
                                 extra={"job": self.id, "chosen_qps": self.qps})
            ip = self.target["ip"]
            self.t0 = time.monotonic()
            self.baseline = self.prober.query(ip, f"www.{self.name}.lab", "A", "baseline", source=self.source)
            time.sleep(COOLDOWN)
            threads = []
            self.t0 = time.monotonic()
            for i, lab in enumerate(labels):
                wait = self.t0 + i / self.qps - time.monotonic()
                if wait > 0:
                    self.stop.wait(wait)
                if self.stop.is_set():
                    break
                th = threading.Thread(target=self._one, args=(i, lab), daemon=True)
                th.start()
                threads.append(th)
            for th in threads:
                th.join()
            self.result = self._final(seed)
            self.state = "done"
        except Exception as e:  # shown in the UI
            self.error, self.state = str(e), "error"
        finally:
            self.finished = time.monotonic()
            app.run_lock.release()

    def _final(self, seed):
        t = self.target
        attempts = [e for e in self.events if e is not None]
        ex = classify_explained(self.baseline, attempts, min_proofs=1)
        answer, headline, detail = explain(ex["label"], self.vantage)
        naive = naive_classify(attempts[0] if attempts else None)
        return {
            "target": self.name, "ip": t["ip"], "answer": answer, "headline": headline, "detail": detail,
            "verdict": ex["label"], "reason": ex["reason"], "rule": ex["rule"],
            "confidence": ex["confidence"], "trace": ex["trace"],
            "naive_verdict": naive, "expected": expected_for(t, self.vantage),
            "correct": ex["label"] in accepted_for(t, self.vantage),
            "lossy_note": t.get("type") == "lossy",
            "configured_limit": t.get("max_qps"),
            "vantage": self.vantage, "vantage_label": self.app.vantages[self.vantage]["label"],
            "source": self.source, "seed": seed,
        }

    def snapshot(self):
        with self.lock:
            slots = [dict(s, i=k + 1) for k, s in enumerate(self.slots)]
            per_second = []
            for sec in range(self.seconds):
                inside = [s for s in slots if s["state"] != "pending" and sec <= s.get("t", 0) < sec + 1]
                per_second.append({
                    "second": sec + 1, "sent": len(inside),
                    "replies": sum(1 for s in inside if s["state"] == "reply"),
                    "seen": sum(1 for s in inside if s.get("seen")),
                })
            for name, i in self.names.items():
                slots[i]["name"] = name
            end = self.finished or time.monotonic()
            return {
                "id": self.id, "state": self.state, "error": self.error,
                "target": self.name, "ip": self.target["ip"], "vantage": self.vantage,
                "vantage_label": self.app.vantages[self.vantage]["label"], "source": self.source,
                "qps": self.qps, "seconds": self.seconds, "stop_early": self.stop_early, "planned": self.planned,
                "sent": self.sent, "replies": self.replies, "seen": self.seen,
                "no_reply": sum(1 for s in slots if s["state"] == "noreply"),
                "not_sent": sum(1 for s in slots if s["state"] == "pending") if self.state != "running" else 0,
                "unique_names": len(self.names) == len(set(self.names)),
                "baseline": summarize(self.baseline), "queries": slots, "per_second": per_second,
                "early": None if self.early is None else {"query": self.early + 1, "answer": "YES"},
                "elapsed": round(end - self.started, 1), "result": self.result,
            }


class App:
    def __init__(self, args):
        cfg = config.load(args.targets)
        self.zone, self.marker = cfg["decoy"]["zone"], cfg["marker_ip"]
        self.targets = {t["name"]: t for t in cfg["targets"]}
        self.vantages = {
            "external": {"label": "External client", "source": cfg["web_ip"],
                         "note": "outside the allowed range, like an Internet client"},
            "internal": {"label": "Internal client", "source": cfg["web_internal_ip"],
                         "note": "inside the allowed range " + str(cfg.get("control_net", ""))},
        }
        self.guard = ScopeGuard([t["ip"] for t in cfg["targets"]], cfg["lab_net"],
                                sources=[v["source"] for v in self.vantages.values()])
        self.decoy = DecoyLog(args.decoy_log)
        out = pathlib.Path(args.out)
        out.mkdir(parents=True, exist_ok=True)
        self.audit = Audit(out / "web-audit.jsonl")
        self.timeout = args.timeout
        self.run_lock = threading.Lock()  # one test at a time keeps rate limits and decoy offsets simple
        self.jobs = {}

    def target_list(self):
        return [{"name": n, "ip": t["ip"]} for n, t in self.targets.items()]

    @staticmethod
    def check_source(source):
        """Fail early with a clear message if this container does not own the source address."""
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.bind((source, 0))
        except OSError as e:
            raise RuntimeError(f"cannot send from {source} ({e.strerror}). The internal alias is added when the web "
                               "container starts; run python generate_lab.py and docker compose up -d --build again.")
        finally:
            sock.close()

    def vantage_list(self):
        return [{"id": k, **v} for k, v in self.vantages.items()]

    def start(self, name, vantage, qps, seconds, stop_early):
        if not self.run_lock.acquire(blocking=False):
            return None
        job = Job(self, name, vantage, qps, seconds, stop_early)
        self.jobs[job.id] = job
        for old in list(self.jobs)[:-20]:  # keep the last 20 only
            self.jobs.pop(old, None)
        threading.Thread(target=job.run, daemon=True).start()
        return job


def make_handler(app):
    class H(BaseHTTPRequestHandler):
        def _send(self, code, body, ctype="application/json"):
            data = body if isinstance(body, bytes) else json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            if self.path == "/":
                self._send(200, INDEX.read_bytes(), "text/html; charset=utf-8")
            elif self.path == "/api/targets":
                self._send(200, app.target_list())
            elif self.path == "/api/vantages":
                self._send(200, app.vantage_list())
            elif self.path == "/api/limits":
                self._send(200, {"max_qps": MAX_RATE, "max_seconds": MAX_SECONDS})
            elif self.path.startswith("/api/job/"):
                job = app.jobs.get(self.path.rsplit("/", 1)[1])
                self._send(200, job.snapshot()) if job else self._send(404, {"error": "unknown job"})
            elif self.path == "/healthz":
                self._send(200, {"ok": True})
            else:
                self._send(404, {"error": "not found"})

        def do_POST(self):
            if self.path != "/api/test":
                return self._send(404, {"error": "not found"})
            try:
                n = int(self.headers.get("Content-Length", 0))
                if n > 1024:
                    return self._send(413, {"error": "request too large"})
                req = json.loads(self.rfile.read(n) or b"{}")
                name, vantage = req.get("target"), req.get("vantage", "external")
                qps, seconds = int(req.get("qps", 1)), int(req.get("seconds", 1))
                stop_early = bool(req.get("stop_early", False))
            except Exception:
                return self._send(400, {"error": "bad request"})
            if name not in app.targets:  # allow-list: names only, never free-text IPs
                return self._send(400, {"error": "unknown target (not in the allow-list)"})
            if vantage not in app.vantages:  # fixed choices only, never a free-text source address
                return self._send(400, {"error": "unknown vantage point"})
            if not 1 <= qps <= MAX_RATE:
                return self._send(400, {"error": f"queries per second must be between 1 and {MAX_RATE}"})
            if not 1 <= seconds <= MAX_SECONDS:
                return self._send(400, {"error": f"duration must be between 1 and {MAX_SECONDS} seconds"})
            job = app.start(name, vantage, qps, seconds, stop_early)
            if job is None:
                return self._send(409, {"error": "another test is still running; wait for it to finish"})
            self._send(200, {"job": job.id})

        def log_message(self, fmt, *a):
            pass

    return H


def main(argv=None):
    ap = argparse.ArgumentParser(prog="rcheck.web")
    ap.add_argument("--targets", default="targets.yaml")
    ap.add_argument("--decoy-log", default="/logs/decoy.log")
    ap.add_argument("--out", default="results")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--timeout", type=float, default=2.0)
    args = ap.parse_args(argv)
    app = App(args)
    srv = ThreadingHTTPServer((args.host, args.port), make_handler(app))
    print(f"RecurseCheck UI on http://{args.host}:{args.port}  ({len(app.targets)} allow-listed targets)", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
