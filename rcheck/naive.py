"""Naive comparison scanner: what a simple 'RA flag' check would conclude.

One query, no baseline, no decoy log, no repeats. It reads only the RA flag and RCODE of
the FIRST decoy reply. Scored on the same evidence as RecurseCheck so the comparison is fair.
"""


def naive_classify(ev):
    if not ev or ev.get("status") != "OK":
        return "Inconclusive"
    rc = ev.get("rcode")
    if rc == "REFUSED":
        return "Refused"
    if rc == "NOERROR" and ev.get("ra") and ev.get("has_answer"):
        return "Recursive"
    if rc == "NOERROR":
        return "Authoritative-only"
    return "Inconclusive"
