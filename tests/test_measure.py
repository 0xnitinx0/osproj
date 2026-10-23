import unittest
from types import SimpleNamespace
from unittest.mock import patch

from blackboxjail.measure import _percentile95, _summary, run_overhead_measurement


class MeasureTests(unittest.TestCase):
    def test_summary_reports_median_and_nearest_rank_p95(self):
        summary = _summary([0.001, 0.002, 0.003, 0.004, 0.020])
        self.assertEqual(summary["samples"], 5)
        self.assertEqual(summary["median_ms"], 3.0)
        self.assertEqual(summary["p95_ms"], 20.0)

    def test_p95_uses_nearest_rank(self):
        self.assertEqual(_percentile95([1.0, 3.0, 2.0]), 3.0)

    def test_empty_summary_rejected(self):
        with self.assertRaises(ValueError):
            _summary([])

    def test_iterations_validation_does_not_launch_workloads(self):
        with self.assertRaisesRegex(ValueError, "between 3 and 100"):
            run_overhead_measurement(iterations=2)

    @patch("blackboxjail.measure.execute", return_value={
        "status": "completed", "metrics": {"elapsed_seconds": 0.012},
    })
    @patch("blackboxjail.measure.subprocess.run", return_value=SimpleNamespace(returncode=0))
    def test_measurement_uses_only_three_built_in_workloads(self, native_run, sandbox_run):
        report = run_overhead_measurement(iterations=3, cgroups="off")
        self.assertEqual(report["iterations_per_mode"], 3)
        self.assertEqual(len(report["workloads"]), 3)
        self.assertTrue(all(item["native"]["samples"] == 3 for item in report["workloads"]))
        self.assertTrue(all(item["sandboxed"]["samples"] == 3 for item in report["workloads"]))
        self.assertEqual(native_run.call_count, 9)
        self.assertEqual(sandbox_run.call_count, 9)


if __name__ == "__main__":
    unittest.main()
