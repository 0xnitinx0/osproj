import json
import os
from pathlib import Path
import tempfile
import unittest

from blackboxjail.events import EventRecorder, redact_command


class EventTests(unittest.TestCase):
    def test_common_secret_flags_are_redacted(self):
        command = ["app", "--password", "supersecret", "--api-key=abc123", "TOKEN=xyz", "--message", "hello"]
        self.assertEqual(
            redact_command(command),
            ["app", "--password", "[REDACTED]", "--api-key=[REDACTED]", "TOKEN=[REDACTED]", "--message", "hello"],
        )

    def test_authorization_header_value_is_redacted(self):
        self.assertEqual(redact_command(["curl", "-H", "Authorization: Bearer xyz"]),
                         ["curl", "-H", "[REDACTED]"])

    def test_event_journal_is_private(self):
        if not hasattr(os, "chmod"):
            self.skipTest("POSIX permissions unavailable")
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "events.jsonl"
            EventRecorder(path).record("privacy_check", content="test")
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            row = json.loads(path.read_text().strip())
            self.assertEqual(len(row["event_hash"]), 64)


if __name__ == "__main__":
    unittest.main()
