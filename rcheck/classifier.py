"""Ordered classification rules. The first matching rule wins.

Inputs are evidence only (replies + decoy log). The ground-truth label is never used here.
classify_explained() also returns the rule that fired, an evidence-strength rating and a
human-readable decision trace, so every verdict can be justified in the report.
"""

LABELS = ["Recursive", "Refused", "Authoritative-only", "Inconclusive"]
FAILURES = {"TIMEOUT", "ERROR", "TC_FAIL"}


def categorize_baseline(ev):
    if ev.get("status") != "OK":
        return ev.get("status", "ERROR")
    rc = ev.get("rcode")
    if rc == "REFUSED":
        return "REFUSED"
    if rc == "SERVFAIL":
        return "SERVFAIL"
    if rc == "NOERROR" and ev.get("aa") and ev.get("has_answer"):
        return "AUTH"
    return "OTHER"


def categorize_decoy(ev):
    if ev.get("status") != "OK":
        return ev.get("status", "ERROR")
    rc = ev.get("rcode")
    if rc == "SERVFAIL":
        return "SERVFAIL"
    if rc == "REFUSED":
        return "REFUSED"
    if rc in ("NOERROR", "NXDOMAIN"):
        if ev.get("marker"):
            if not ev.get("seen"):
                return "NO_DECOY_EVIDENCE"  # returns the marker but never asked the decoy
            if rc == "NOERROR" and ev.get("ra"):
                return "RECURSIVE"
            return "RA_MISSING"
        if not ev.get("seen"):
            return "NOANSWER"
    return "OTHER"


def describe(ev, cat, decoy=True):
    """One-line description of a single query's evidence."""
    if ev.get("status") != "OK":
        return f"{cat} ({ev.get('error') or 'no reply'})"
    ans = "marker" if ev.get("marker") else ("yes" if ev.get("has_answer") else "none")
    s = f"{cat} (rcode={ev.get('rcode')}, RA={int(ev.get('ra', 0))}, AA={int(ev.get('aa', 0))}, answer={ans}"
    if decoy:
        s += f", seen in decoy log={'yes' if ev.get('seen') else 'no'}"
    return s + ")"


def classify_explained(baseline, attempts, min_proofs=None):
    """Return {label, reason, rule, confidence, trace}.

    min_proofs=None is the strict policy used for scored runs: Recursive needs every attempt proven.
    min_proofs=1 is the first-proof policy: one query whose unique name reached the decoy server and
    came back with the marker is enough, because that lookup could only have been made by recursion.
    """
    if not baseline or not attempts:
        return {"label": "Inconclusive", "reason": "ABORTED", "rule": 4,
                "confidence": "n/a", "trace": ["run aborted before enough evidence was collected"]}
    b = categorize_baseline(baseline)
    cats = [categorize_decoy(a) for a in attempts]
    u = set(cats)
    trace = ["baseline: " + describe(baseline, b, decoy=False)]
    trace += [f"decoy attempt {i + 1}: " + describe(a, c) for i, (a, c) in enumerate(zip(attempts, cats))]

    def out(label, reason, rule, conf, why):
        return {"label": label, "reason": reason, "rule": rule, "confidence": conf,
                "trace": trace + [f"rule {rule} fired: {why}"]}

    # 1a. first-proof policy: enough proven lookups (positive evidence needs no baseline)
    if min_proofs is not None:
        proven = [i for i, c in enumerate(cats) if c == "RECURSIVE"]
        if len(proven) >= min_proofs:
            lost = sum(1 for c in cats if c in FAILURES)
            extra = f"; {lost} other quer{'y' if lost == 1 else 'ies'} got no reply" if lost else ""
            return out("Recursive", "RA+marker+decoy_log", 1, "high",
                       f"decoy attempt {proven[0] + 1} returned RA=1 + marker AND the decoy logged its unique name: "
                       f"{len(proven)} of {len(attempts)} queries proven recursive (one proof is enough){extra}")
    # 1. Recursive: every attempt had RA=1, NOERROR, marker answer AND appeared in the decoy log
    if u == {"RECURSIVE"} and b not in FAILURES | {"REFUSED"}:
        return out("Recursive", "RA+marker+decoy_log", 1, "high",
                   f"all {len(attempts)} attempts returned RA=1 + marker AND the decoy logged each unique name "
                   "(positive proof the server performed the lookup itself)")
    # 2. Refused: baseline and all decoy attempts REFUSED
    if b == "REFUSED" and u == {"REFUSED"}:
        return out("Refused", "REFUSED_BASELINE_AND_DECOY", 2, "high",
                   "baseline and every decoy attempt returned REFUSED (explicit policy denial to this client)")
    # 3. Authoritative-only: baseline AA answer, decoy got nothing and never reached the decoy
    if b == "AUTH" and u <= {"NOANSWER", "REFUSED"}:
        return out("Authoritative-only", "AA_BASELINE_NO_DECOY", 3, "medium",
                   "baseline answered authoritatively (AA=1) but no decoy name produced an answer or a decoy log "
                   "entry (negative evidence, so confidence is medium)")
    # 4. Inconclusive, with a reason
    if len(u) > 1:
        return out("Inconclusive", "CONFLICT", 4, "n/a", "attempts disagreed: " + ", ".join(cats))
    only = next(iter(u))
    if only in ("TIMEOUT", "SERVFAIL", "TC_FAIL", "NO_DECOY_EVIDENCE", "ERROR"):
        why = {
            "NO_DECOY_EVIDENCE": "the server returned the marker answer but the decoy never saw the name "
                                  "(answer not obtained by real recursion: fabricated or injected)",
            "TIMEOUT": "no reply to any decoy attempt",
            "SERVFAIL": "every decoy attempt returned SERVFAIL",
            "TC_FAIL": "reply was truncated and the TCP retry failed",
            "ERROR": "transport error on every attempt",
        }[only]
        return out("Inconclusive", only, 4, "n/a", why)
    if b in FAILURES | {"SERVFAIL"}:
        return out("Inconclusive", "BASELINE_" + b, 4, "n/a", "baseline did not give a usable reply: " + b)
    return out("Inconclusive", "OTHER", 4, "n/a", "evidence matched none of rules 1-3")


def classify(baseline, attempts):
    """Return (label, reason)."""
    r = classify_explained(baseline, attempts)
    return r["label"], r["reason"]
