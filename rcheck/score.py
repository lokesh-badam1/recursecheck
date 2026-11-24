"""Ground-truth comparison: confusion matrix, precision/recall, coverage."""
from collections import Counter

from .classifier import LABELS


def score(rows):
    """rows: dicts with 'expected', 'verdict', 'reason'."""
    cm = {e: {p: 0 for p in LABELS} for e in LABELS}
    for r in rows:
        cm[r["expected"]][r["verdict"]] += 1
    n = len(rows)
    correct = sum(cm[l][l] for l in LABELS)
    per_class = {}
    for l in LABELS:
        tp = cm[l][l]
        predicted = sum(cm[e][l] for e in LABELS)
        actual = sum(cm[l].values())
        per_class[l] = {
            "precision": round(tp / predicted, 3) if predicted else None,
            "recall": round(tp / actual, 3) if actual else None,
            "support": actual,
        }
    decided = sum(1 for r in rows if r["verdict"] != "Inconclusive")
    return {
        "targets": n,
        "accuracy": round(correct / n, 3) if n else None,
        "coverage": round(decided / n, 3) if n else None,  # share that got a definite label
        "confusion_matrix": cm,
        "per_class": per_class,
        "inconclusive_by_reason": dict(Counter(r["reason"] for r in rows if r["verdict"] == "Inconclusive")),
    }


def format_report(m):
    w = max(len(l) for l in LABELS) + 2
    out = ["", "Confusion matrix (rows = expected, columns = predicted)"]
    out.append(" " * w + "".join(l[:12].ljust(14) for l in LABELS))
    for e in LABELS:
        out.append(e.ljust(w) + "".join(str(m["confusion_matrix"][e][p]).ljust(14) for p in LABELS))
    out.append("")
    for l, v in m["per_class"].items():
        out.append(f"{l:20s} precision={v['precision']}  recall={v['recall']}  support={v['support']}")
    out.append("")
    out.append(f"accuracy={m['accuracy']}  coverage={m['coverage']}  targets={m['targets']}")
    out.append(f"inconclusive by reason: {m['inconclusive_by_reason']}")
    return "\n".join(out)


def format_comparison(rows, ours, naive):
    out = ["", "RecurseCheck vs naive single-query RA-flag scanner (same evidence, no baseline/decoy log/repeats)"]
    out.append(f"  accuracy:  RecurseCheck={ours['accuracy']}   naive={naive['accuracy']}")
    out.append(f"  coverage:  RecurseCheck={ours['coverage']}   naive={naive['coverage']}")
    wins = [r for r in rows if r["correct"] and not r["naive_correct"]]
    losses = [r for r in rows if r["naive_correct"] and not r["correct"]]
    out.append(f"  RecurseCheck right, naive wrong ({len(wins)}): "
               + (", ".join(f"{r['target']} (expected {r['expected']}, naive said {r['naive_verdict']})" for r in wins) or "none"))
    out.append(f"  naive right, RecurseCheck wrong ({len(losses)}): "
               + (", ".join(r["target"] for r in losses) or "none"))
    return "\n".join(out)
