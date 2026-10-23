import unittest

from blackboxjail.analyzer import analyze_report


class AnalyzerTests(unittest.TestCase):
    def test_timeout_finding_links_to_evidence(self):
        report = {
            "status": "timeout", "exit_code": 124,
            "limits": {"timeout_seconds": 1},
            "metrics": {"elapsed_seconds": 1.0},
            "events": [{"event_id": "evt-1", "event": "timeout"}],
            "observations": {"samples": []},
        }
        result = analyze_report(report)
        finding = result["analysis"]["findings"][0]
        self.assertEqual(finding["rule_id"], "TIME-001")
        self.assertIn("evt-1", finding["evidence_event_ids"])

    def test_completed_run_gets_fingerprint_and_normal_finding(self):
        report = {"status": "completed", "exit_code": 0, "limits": {}, "metrics": {},
                  "events": [{"event_id": "evt-2", "event": "run_finished"}],
                  "observations": {"samples": []}}
        result = analyze_report(report)
        self.assertEqual(result["analysis"]["fingerprint"]["workload_class"], "general_or_lightweight")
        self.assertEqual(result["analysis"]["findings"][0]["rule_id"], "RUN-OK-001")

    def test_nonzero_exit_does_not_claim_specific_root_cause(self):
        report = {"status": "failed", "exit_code": 23, "termination_signal": None,
                  "limits": {}, "metrics": {}, "events": [], "observations": {"samples": []}}
        result = analyze_report(report)
        finding = result["analysis"]["findings"][0]
        self.assertEqual(finding["rule_id"], "CRASH-001")
        self.assertIn("not established", finding["summary"])


if __name__ == "__main__":
    unittest.main()
