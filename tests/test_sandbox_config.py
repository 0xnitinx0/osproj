from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from blackboxjail.sandbox import (build_bwrap_command, execute, SandboxError, _probe_network_namespace_support)


class SandboxConfigTests(unittest.TestCase):
    @patch("blackboxjail.sandbox.shutil.which", return_value="/usr/bin/bwrap")
    def test_bwrap_config_uses_empty_namespaces_and_size_bounded_tmpfs(self, _which):
        with tempfile.TemporaryDirectory() as tmp:
            command = build_bwrap_command(["/bin/echo", "hi"], Path(tmp), False,
                                          {"LANG": "C"}, seccomp_fd=77, tmpfs_limit_bytes=128*1024*1024)
        self.assertIn("--unshare-all", command)
        self.assertIn("--cap-drop", command)
        self.assertIn("ALL", command)
        self.assertIn("--seccomp", command)
        self.assertIn("77", command)
        self.assertIn("--size", command)
        self.assertIn(str(64 * 1024 * 1024), command)
        self.assertIn("--tmpfs", command)
        if Path("/usr/local").exists():
            self.assertIn("/usr/local", command)
        self.assertNotIn("SECRET_TOKEN", command)
        self.assertNotIn("--share-net", command)

    @patch("blackboxjail.sandbox.subprocess.run")
    @patch("blackboxjail.sandbox.shutil.which", return_value="/usr/bin/bwrap")
    def test_probe_recognizes_bubblewrap_loopback_permission_failure(self, _which, mock_run):
        _probe_network_namespace_support.cache_clear()
        mock_run.return_value = __import__("subprocess").CompletedProcess(
            ["/usr/bin/bwrap"], 1, b"", b"bwrap: loopback: Failed RTM_NEWADDR: Operation not permitted"
        )
        result = _probe_network_namespace_support("/usr/bin/bwrap")
        self.assertEqual(result[0], "restricted")
        self.assertIn("RTM_NEWADDR", result[1])
        _probe_network_namespace_support.cache_clear()

    @patch("blackboxjail.sandbox.shutil.which", return_value="/usr/bin/bwrap")
    def test_network_restricted_fallback_keeps_other_namespaces_and_shares_net_explicitly(self, _which):
        with tempfile.TemporaryDirectory() as tmp:
            command = build_bwrap_command(["/bin/true"], Path(tmp), False, {},
                                          unshare_network=False)
        self.assertIn("--unshare-user", command)
        self.assertIn("--unshare-pid", command)
        self.assertIn("--unshare-ipc", command)
        self.assertIn("--unshare-uts", command)
        self.assertIn("--share-net", command)
        self.assertNotIn("--unshare-all", command)
        self.assertNotIn("--unshare-net", command)

    @patch("blackboxjail.sandbox.shutil.which", return_value="/usr/bin/bwrap")
    def test_network_is_only_shared_when_requested(self, _which):
        with tempfile.TemporaryDirectory() as tmp:
            command = build_bwrap_command(["/bin/true"], Path(tmp), True, {})
        self.assertIn("--share-net", command)

    def test_nonfinite_timeout_is_rejected_before_launch(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(SandboxError, "finite positive"):
                execute(["/bin/true"], workspace=tmp, timeout_seconds=float("nan"))
            with self.assertRaisesRegex(SandboxError, "finite positive"):
                execute(["/bin/true"], workspace=tmp, timeout_seconds=float("inf"))

    def test_system_paths_cannot_be_selected_as_writable_workspace(self):
        if not Path("/proc/self/stat").exists():
            self.skipTest("Linux-only validation")
        for protected in ("/etc", "/usr", "/tmp", str(Path.home())):
            with self.subTest(protected=protected):
                with self.assertRaises(SandboxError):
                    execute(["/bin/true"], workspace=protected)

    @patch("blackboxjail.sandbox.shutil.which", return_value=None)
    def test_missing_bubblewrap_is_actionable(self, _which):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(SandboxError):
                build_bwrap_command(["/bin/true"], Path(tmp), False, {})


if __name__ == "__main__":
    unittest.main()
