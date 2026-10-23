import json
from pathlib import Path
import tempfile
import unittest

from blackboxjail.policy import DEFAULT_POLICY, load_policy


class PolicyTests(unittest.TestCase):
    def test_defaults(self):
        self.assertEqual(load_policy(None), DEFAULT_POLICY)
        self.assertTrue(DEFAULT_POLICY["seccomp"])
        self.assertEqual(DEFAULT_POLICY["cgroups"], "auto")

    def test_valid_overrides(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "policy.json"
            path.write_text(json.dumps({"timeout_seconds": 7, "network": True}), encoding="utf-8")
            result = load_policy(str(path))
            self.assertEqual(result["timeout_seconds"], 7)
            self.assertTrue(result["network"])
            self.assertEqual(result["memory_limit_mb"], DEFAULT_POLICY["memory_limit_mb"])

    def test_unknown_key_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "policy.json"
            path.write_text(json.dumps({"unsafe_mode": True}), encoding="utf-8")
            with self.assertRaises(ValueError):
                load_policy(str(path))

    def test_invalid_limit_rejected(self):
        for bad in (0, -1, True, 1.5):
            with self.subTest(bad=bad), tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / "policy.json"
                path.write_text(json.dumps({"max_processes": bad}), encoding="utf-8")
                with self.assertRaises(ValueError):
                    load_policy(str(path))

    def test_invalid_cgroup_mode_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "policy.json"
            path.write_text(json.dumps({"cgroups": "magic"}), encoding="utf-8")
            with self.assertRaises(ValueError):
                load_policy(str(path))


if __name__ == "__main__":
    unittest.main()
