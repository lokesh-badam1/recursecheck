import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from rcheck.classifier import classify, classify_explained  # noqa: E402
from rcheck.naive import naive_classify  # noqa: E402


def base(kind):
    return {
        "auth": {"status": "OK", "rcode": "NOERROR", "aa": True, "has_answer": True},
        "refused": {"status": "OK", "rcode": "REFUSED"},
        "timeout": {"status": "TIMEOUT"},
    }[kind]


REC = {"status": "OK", "rcode": "NOERROR", "ra": True, "marker": True, "has_answer": True, "seen": True}
REF = {"status": "OK", "rcode": "REFUSED"}
TO = {"status": "TIMEOUT"}
SF = {"status": "OK", "rcode": "SERVFAIL"}
LIAR = {"status": "OK", "rcode": "NOERROR", "ra": True, "marker": True, "has_answer": True, "seen": False}


class T(unittest.TestCase):
    def test_recursive(self):
        self.assertEqual(classify(base("auth"), [REC] * 3), ("Recursive", "RA+marker+decoy_log"))

    def test_refused(self):
        self.assertEqual(classify(base("refused"), [REF] * 3)[0], "Refused")

    def test_auth_only(self):
        self.assertEqual(classify(base("auth"), [REF] * 3)[0], "Authoritative-only")

    def test_timeout(self):
        self.assertEqual(classify(base("timeout"), [TO] * 3), ("Inconclusive", "TIMEOUT"))

    def test_servfail(self):
        self.assertEqual(classify(base("auth"), [SF] * 3), ("Inconclusive", "SERVFAIL"))

    def test_conflict(self):
        self.assertEqual(classify(base("auth"), [REC, TO, REC]), ("Inconclusive", "CONFLICT"))

    def test_marker_without_decoy_log_is_not_recursive(self):
        self.assertEqual(classify(base("auth"), [LIAR] * 3), ("Inconclusive", "NO_DECOY_EVIDENCE"))

    def test_baseline_lost_blocks_recursive(self):
        self.assertEqual(classify(base("timeout"), [REC] * 3)[0], "Inconclusive")

    def test_aborted(self):
        self.assertEqual(classify(None, []), ("Inconclusive", "ABORTED"))

    def test_explanation_has_rule_confidence_trace(self):
        ex = classify_explained(base("auth"), [REC] * 3)
        self.assertEqual((ex["rule"], ex["confidence"]), (1, "high"))
        self.assertEqual(len(ex["trace"]), 5)  # baseline + 3 attempts + rule line
        self.assertEqual(classify_explained(base("auth"), [REF] * 3)["confidence"], "medium")

    def test_naive_scanner_is_fooled_where_recursecheck_is_not(self):
        self.assertEqual(naive_classify(LIAR), "Recursive")
        self.assertEqual(classify(base("auth"), [LIAR] * 3)[0], "Inconclusive")
        # no baseline: naive cannot tell authoritative-only from policy refusal
        self.assertEqual(naive_classify(REF), "Refused")


if __name__ == "__main__":
    unittest.main()


class VantageTests(unittest.TestCase):
    def test_expected_depends_on_vantage(self):
        from rcheck.web import expected_for
        refusing = {"type": "refusing", "expected": "Refused"}
        open_ = {"type": "open", "expected": "Recursive"}
        self.assertEqual(expected_for(refusing, "external"), "Refused")
        self.assertEqual(expected_for(refusing, "internal"), "Recursive")
        self.assertEqual(expected_for(open_, "internal"), "Recursive")

    def test_guard_only_allows_approved_sources(self):
        from rcheck.guard import ScopeGuard, ScopeViolation
        g = ScopeGuard(["10.10.0.11"], "10.10.0.0/16", sources=["10.10.2.20", "10.10.1.20"])
        g.check("10.10.0.11", "A", "10.10.1.20")
        with self.assertRaises(ScopeViolation):
            g.check("10.10.0.11", "A", "10.10.9.9")
        with self.assertRaises(ScopeViolation):
            ScopeGuard(["10.10.0.11"], "10.10.0.0/16", sources=["8.8.8.8"])


class FirstProofTests(unittest.TestCase):
    BASE = {"status": "OK", "rcode": "NOERROR", "aa": True, "ra": True, "has_answer": True, "answers": ["10.0.0.1"]}

    def ok(self, seen=True):
        return {"status": "OK", "rcode": "NOERROR", "ra": True, "aa": False, "has_answer": True,
                "answers": ["192.0.2.123"], "marker": True, "seen": seen}

    def test_one_proof_among_dropped_queries_is_yes(self):
        att = [self.ok()] + [{"status": "TIMEOUT"}] * 9      # resolver limits itself: 1 of 10 answered
        r = classify_explained(self.BASE, att, min_proofs=1)
        self.assertEqual((r["label"], r["rule"]), ("Recursive", 1))
        # the strict scored policy still refuses to call this Recursive
        self.assertEqual(classify_explained(self.BASE, att)["label"], "Inconclusive")

    def test_marker_without_decoy_log_is_not_a_proof(self):
        att = [self.ok(seen=False)] + [{"status": "TIMEOUT"}] * 3
        self.assertNotEqual(classify_explained(self.BASE, att, min_proofs=1)["label"], "Recursive")

    def test_no_proof_falls_back_to_normal_rules(self):
        refused = {"status": "OK", "rcode": "REFUSED", "ra": True, "aa": False}
        r = classify_explained(refused, [refused, refused, refused], min_proofs=1)
        self.assertEqual(r["label"], "Refused")

    def test_rate_ceiling(self):
        from rcheck.rate import RateController, MAX_RATE
        RateController(MAX_RATE, MAX_RATE)
        with self.assertRaises(ValueError):
            RateController(MAX_RATE + 1, 5)

    def test_lossy_accepts_either_label(self):
        from rcheck.web import accepted_for
        self.assertEqual(accepted_for({"type": "lossy", "expected": "Inconclusive"}, "external"),
                         {"Inconclusive", "Recursive"})
