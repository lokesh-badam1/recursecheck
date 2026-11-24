"""Probe engine: sends one small A/TXT query and records the evidence."""
import datetime
import time

import dns.exception
import dns.flags
import dns.message
import dns.query
import dns.rcode


class Prober:
    def __init__(self, guard, rates, audit, stop, decoy, marker, timeout=2.0, dry_run=False, retries=0,
                 hook=None, extra=None):
        self.guard, self.rates, self.audit, self.stop = guard, rates, audit, stop
        self.decoy, self.marker, self.timeout, self.dry_run = decoy, marker, timeout, dry_run
        self.retries = retries  # extra sends after a timeout (each one is rate limited too)
        self.hook = hook        # optional callback hook(kind, ev): kind is "sent" or "done"
        self.extra = extra or {}  # extra fields copied into every audit record (e.g. job id, chosen rate)

    def query(self, ip, qname, qtype="A", phase="decoy", label=None, source=None):
        self.guard.check(ip, qtype, source)
        if not self.rates.acquire(ip, self.stop):
            return None  # aborted by kill switch
        ev = {
            "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "phase": phase, "ip": ip, "qname": qname, "qtype": qtype,
        }
        ev.update(self.extra)
        if source:
            ev["source"] = source  # vantage point the query was sent from
        if self.dry_run:
            ev["status"] = "DRYRUN"
            self.audit.write(ev)
            return ev

        if self.hook:
            self.hook("sent", ev)
        q = dns.message.make_query(qname, qtype)  # RD=1 by default
        resp = None
        t0 = time.monotonic()
        ev["tries"] = 0
        for i in range(self.retries + 1):
            if i and not self.rates.acquire(ip, self.stop):
                break  # kill switch during a retry
            ev["tries"] += 1
            try:
                resp = dns.query.udp(q, ip, timeout=self.timeout, source=source)
                ev["proto"] = "udp"
                if resp.flags & dns.flags.TC:
                    ev["tc"] = True
                    try:
                        resp = dns.query.tcp(q, ip, timeout=self.timeout, source=source)
                        ev["proto"] = "tcp"
                    except Exception as e:
                        resp = None
                        ev["status"], ev["error"] = "TC_FAIL", repr(e)
                break
            except dns.exception.Timeout:
                ev["status"] = "TIMEOUT"  # retry if allowed
            except Exception as e:
                ev["status"], ev["error"] = "ERROR", repr(e)
                break
        ev["rtt_ms"] = round((time.monotonic() - t0) * 1000, 1)

        if resp is not None:
            ev["status"] = "OK"
            ev["rcode"] = dns.rcode.to_text(resp.rcode())
            ev["ra"] = bool(resp.flags & dns.flags.RA)
            ev["aa"] = bool(resp.flags & dns.flags.AA)
            answers = [r.to_text() for rrset in resp.answer for r in rrset]
            ev["answers"] = answers
            ev["has_answer"] = bool(answers)
            ev["marker"] = self.marker in answers

        if label:
            patient = ev.get("status") == "OK" and ev.get("marker")
            ev["seen"] = self.decoy.wait_seen(label, patient)
        self.audit.write(ev)
        if self.hook:
            self.hook("done", ev)
        return ev
