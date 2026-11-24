"""RecurseCheck runner.  Usage (inside the probe container):

    python -m rcheck.run --targets targets.yaml            # real run
    python -m rcheck.run --targets targets.yaml --dry-run  # print plan, send nothing
    python -m rcheck.run --replay results/<run>/config.json
"""
import argparse
import csv
import json
import pathlib
import random
import signal
import threading
import time

from . import config
from .audit import Audit
from .decoylog import DecoyLog
from .engine import probe_target
from .classifier import categorize_baseline, categorize_decoy, classify_explained
from .naive import naive_classify
from .guard import ScopeGuard, ScopeViolation
from .probe import Prober
from .rate import RateController
from .score import format_comparison, format_report, score


def parse_args(argv):
    ap = argparse.ArgumentParser(prog="rcheck.run")
    ap.add_argument("--targets", default="targets.yaml")
    ap.add_argument("--decoy-log", default="/logs/decoy.log")
    ap.add_argument("--out", default="results")
    ap.add_argument("--seed", type=int)
    ap.add_argument("--attempts", type=int, default=3)
    ap.add_argument("--timeout", type=float, default=2.0)
    ap.add_argument("--retries", type=int, default=0, help="extra sends after a timeout (rate limited)")
    ap.add_argument("--target-rate", type=float, default=1.0, help="queries/s per target")
    ap.add_argument("--global-rate", type=float, default=5.0, help="queries/s overall")
    ap.add_argument("--only", help="comma-separated target names")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--replay", help="config.json of an earlier run")
    return ap.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    if args.replay:
        old = json.loads(pathlib.Path(args.replay).read_text())
        for k in ("seed", "attempts", "timeout", "retries", "target_rate", "global_rate", "only"):
            setattr(args, k, old.get(k, getattr(args, k)))
    if args.seed is None:
        args.seed = int(time.time())

    cfg = config.load(args.targets)
    zone, marker = cfg["decoy"]["zone"], cfg["marker_ip"]
    all_targets = cfg["targets"]
    try:
        guard = ScopeGuard([t["ip"] for t in all_targets], cfg["lab_net"])
    except ScopeViolation as e:
        raise SystemExit(f"SCOPE GUARD: {e}")

    wanted = set(args.only.split(",")) if args.only else None
    targets = [t for t in all_targets if not wanted or t["name"] in wanted]

    decoy = DecoyLog(args.decoy_log)
    if not args.dry_run and not decoy.exists():
        raise SystemExit(f"decoy log not found: {args.decoy_log} (is the lab up?)")
    decoy.mark()

    run_dir = pathlib.Path(args.out) / f"run-{time.strftime('%Y%m%d-%H%M%S')}-seed{args.seed}"
    run_dir.mkdir(parents=True)
    (run_dir / "config.json").write_text(json.dumps({
        "seed": args.seed, "attempts": args.attempts, "timeout": args.timeout, "retries": args.retries,
        "target_rate": args.target_rate, "global_rate": args.global_rate,
        "only": args.only, "targets_file": args.targets, "zone": zone, "marker": marker,
        "dry_run": args.dry_run,
    }, indent=2))

    stop = threading.Event()

    def on_sigint(sig, frame):
        print("\n[kill switch] Ctrl+C received: stopping after the current query...")
        stop.set()

    signal.signal(signal.SIGINT, on_sigint)

    audit = Audit(run_dir / "audit.jsonl")
    prober = Prober(guard, RateController(args.target_rate, args.global_rate), audit, stop,
                    decoy, marker, args.timeout, args.dry_run, args.retries)
    rng = random.Random(args.seed)
    print(f"run dir: {run_dir}  seed={args.seed}  targets={len(targets)}  dry_run={args.dry_run}")

    rows, evidence = [], []
    for t in targets:
        if stop.is_set():
            break
        ip, name = t["ip"], t["name"]
        base, attempts = probe_target(prober, t, zone, rng, args.attempts, stop)

        if args.dry_run:
            print(f"  [dry-run] {name} {ip}: 1 baseline + {args.attempts} decoy queries planned")
            continue
        if stop.is_set() and (base is None or len(attempts) < args.attempts):
            ex = {"label": "Inconclusive", "reason": "ABORTED", "rule": 4, "confidence": "n/a",
                  "trace": ["run aborted (kill switch) before enough evidence was collected"]}
        else:
            ex = classify_explained(base, attempts)
        verdict, reason = ex["label"], ex["reason"]
        naive = naive_classify(attempts[0] if attempts else None)
        exp = t["expected"]
        rows.append({
            "target": name, "ip": ip, "expected": exp, "verdict": verdict, "reason": reason,
            "correct": verdict == exp, "confidence": ex["confidence"],
            "naive_verdict": naive, "naive_correct": naive == exp,
            "baseline": categorize_baseline(base) if base else "",
            "attempts": "|".join(categorize_decoy(a) for a in attempts),
        })
        evidence.append({"target": name, "baseline": base, "attempts": attempts,
                         "verdict": verdict, "reason": reason, "explanation": ex, "naive_verdict": naive})
        flag = "OK " if verdict == exp else "BAD"
        print(f"  {flag} {name} {ip:12s} -> {verdict:18s} ({reason})  expected {exp}  | naive: {naive}")

    audit.close()
    if args.dry_run:
        print("dry run finished: nothing was sent.")
        return 0

    with open(run_dir / "results.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()) if rows else ["target"])
        w.writeheader()
        w.writerows(rows)
    (run_dir / "evidence.json").write_text(json.dumps(evidence, indent=2))
    metrics = score(rows)
    naive_metrics = score([{**r, "verdict": r["naive_verdict"], "reason": "NAIVE"} for r in rows])
    metrics["naive_baseline"] = naive_metrics
    (run_dir / "metrics.json").write_text(json.dumps(metrics, indent=2))
    report = format_report(metrics) + "\n" + format_comparison(rows, metrics, naive_metrics)
    (run_dir / "report.txt").write_text(report)
    print(report)
    try:
        from .report import build
        print(f"\nexposure report: {build(run_dir)}")
    except Exception as e:  # the report must never break a run
        print(f"\n(exposure report not generated: {e})")
    print(f"files written to {run_dir}/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
