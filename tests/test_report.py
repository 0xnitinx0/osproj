import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from blackboxjail.report import reports_dir, save_report, state_dir


class ReportTests(unittest.TestCase):
    def test_state_and_report_files_are_private(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.dict(os.environ, {"XDG_STATE_HOME": tmp}):
                folder = state_dir()
                report = {"run_id": "test-report", "status": "completed", "stdout": "private"}
                path = save_report(report)
                self.assertEqual(folder.stat().st_mode & 0o777, 0o700)
                self.assertEqual(reports_dir().stat().st_mode & 0o777, 0o700)
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
