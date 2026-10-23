import json
from pathlib import Path
import tempfile
import unittest

from blackboxjail.audit import verify_journal
from blackboxjail.events import EventRecorder


class AuditTests(unittest.TestCase):
    def test_fresh_hash_chain_verifies(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "events.jsonl"
            recorder = EventRecorder(path)
            recorder.record("test_started", run_id="r1")
            recorder.record("test_finished", run_id="r1", status="ok")
            result = verify_journal(path)
            self.assertTrue(result["valid"], result["errors"])
            self.assertEqual(result["checked"], 2)
            self.assertTrue(result["complete"])

    def test_tampering_is_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "events.jsonl"
            recorder = EventRecorder(path)
            recorder.record("security_event", detail="original")
            rows = path.read_text(encoding="utf-8").splitlines()
            event = json.loads(rows[0])
            event["detail"] = "tampered"
            path.write_text(json.dumps(event) + "\n", encoding="utf-8")
            result = verify_journal(path)
            self.assertFalse(result["valid"])
            self.assertTrue(result["errors"])

    def test_legacy_rows_are_reported_but_not_misrepresented_as_hashed(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "events.jsonl"
            path.write_text('{"event":"old"}\n', encoding="utf-8")
            result = verify_journal(path)
            self.assertTrue(result["valid"])
            self.assertFalse(result["complete"])
            self.assertEqual(result["legacy_unhashed_lines"], 1)
            self.assertEqual(result["checked"], 0)
            self.assertFalse(result["complete"])


if __name__ == "__main__":
    unittest.main()
