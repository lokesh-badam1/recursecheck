"""Shared probing sequence for one target (used by the CLI runner and the web UI)."""


def probe_target(prober, target, zone, rng, attempts, stop=None, source=None):
    """Baseline query, then `attempts` decoy queries with fresh unique names.

    Returns (baseline_evidence, [decoy_evidence, ...]).
    """
    ip, name = target["ip"], target["name"]
    base = prober.query(ip, f"www.{name}.lab", "A", "baseline", source=source)
    results = []
    for _ in range(attempts):
        if stop is not None and stop.is_set():
            break
        label = "rc" + format(rng.getrandbits(40), "010x")
        ev = prober.query(ip, f"{label}.{zone}", "A", "decoy", label=label, source=source)
        if ev is None:
            break
        results.append(ev)
    return base, results
