import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

from blackboxjail.benchmark import save_benchmark_report


class BenchmarkReportTests(unittest.TestCase):
    def test_suite_summary_is_json_and_owner_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch("blackboxjail.benchmark.state_dir", return_value=Path(tmp)):
                path = save_benchmark_report({
                    "suite_id": "unit-test-suite",
                    "passed": 2,
                    "total": 2,
                    "all_passed": True,
                })
            self.assertEqual(json.loads(path.read_text())['all_passed'], True)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)


if __name__ == "__main__":
    unittest.main()
