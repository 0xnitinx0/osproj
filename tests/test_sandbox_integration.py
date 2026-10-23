import shutil
import tempfile
import unittest
from pathlib import Path

from blackboxjail.sandbox import execute


@unittest.skipUnless(shutil.which("bwrap"), "bubblewrap is not installed in this environment")
class SandboxIntegrationTests(unittest.TestCase):
    def test_echo_runs_in_sandbox_with_seccomp(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = execute(
                ["/bin/echo", "hello from sandbox"], workspace=tmp,
                timeout_seconds=4, cpu_seconds=2, memory_limit_mb=256, max_output_kb=32,
            )
        self.assertEqual(result["status"], "completed", result.get("error", result.get("stderr")))
        self.assertIn("hello from sandbox", result["stdout"])
        self.assertTrue(result["sandbox"]["seccomp_enabled"])

    def test_host_home_is_not_exposed_as_home(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = execute(
                ["/bin/sh", "-c", "printf '%s' \"$HOME\""], workspace=tmp,
                timeout_seconds=4, cpu_seconds=2, memory_limit_mb=256, max_output_kb=32,
            )
        self.assertEqual(result["status"], "completed", result.get("error", result.get("stderr")))
        self.assertEqual(result["stdout"], "/tmp")

    def test_output_is_capped_without_a_temporary_output_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = execute(
                ["/usr/bin/yes", "blackboxjail"], workspace=tmp, timeout_seconds=4,
                cpu_seconds=2, memory_limit_mb=256, max_output_kb=2,
            )
        self.assertEqual(result["status"], "output_limit_exceeded", result.get("stderr"))
        self.assertLessEqual(result["metrics"]["stdout_bytes_captured"], 2048)

    def test_timeout_kills_sleep(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = execute(
                ["/bin/sleep", "3"], workspace=tmp, timeout_seconds=0.25,
                cpu_seconds=2, memory_limit_mb=256, max_output_kb=16,
            )
        self.assertEqual(result["status"], "timeout")
        self.assertEqual(result["exit_code"], 124)

    def test_seccomp_denies_ptrace(self):
        import sys
        code = ("import ctypes; c=ctypes.CDLL(None,use_errno=True); r=c.ptrace(0,0,None,None); "
                "print('BLOCKED' if r == -1 and ctypes.get_errno() == 1 else 'UNEXPECTED')")
        with tempfile.TemporaryDirectory() as tmp:
            result = execute(
                [sys.executable, "-c", code], workspace=tmp, timeout_seconds=4,
                cpu_seconds=2, memory_limit_mb=256, max_output_kb=16,
            )
        self.assertEqual(result["status"], "completed", result.get("error", result.get("stderr")))
        self.assertIn("BLOCKED", result["stdout"])


if __name__ == "__main__":
    unittest.main()
