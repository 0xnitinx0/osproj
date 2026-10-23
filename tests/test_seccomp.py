import struct
import unittest
from unittest.mock import patch

from blackboxjail.seccomp import ARCHITECTURES, build_denylist_filter, current_architecture, denied_syscalls


class SeccompTests(unittest.TestCase):
    def test_compiled_program_is_sock_filter_aligned(self):
        program = build_denylist_filter()
        self.assertGreater(len(program), 8 * 10)
        self.assertEqual(len(program) % 8, 0)

    def test_profile_contains_expected_kernel_escape_controls(self):
        names = denied_syscalls()
        for name in ("mount", "ptrace", "bpf", "unshare", "setns", "perf_event_open"):
            self.assertIn(name, names)

    def test_architecture_aliases(self):
        with patch("blackboxjail.seccomp.platform.machine", return_value="arm64"):
            self.assertEqual(current_architecture(), "aarch64")

    def test_unknown_architecture_fails_closed(self):
        with patch("blackboxjail.seccomp.platform.machine", return_value="mips64"):
            with self.assertRaises(ValueError):
                build_denylist_filter()

    def test_supported_arches_have_distinct_audit_ids(self):
        self.assertNotEqual(ARCHITECTURES["x86_64"][0], ARCHITECTURES["aarch64"][0])

    def test_x86_64_filter_rejects_x32_syscall_number_bit(self):
        with patch("blackboxjail.seccomp.platform.machine", return_value="x86_64"):
            program = build_denylist_filter()
        instructions = [struct.unpack("=HBBI", program[i:i + 8])
                        for i in range(0, len(program), 8)]
        # BPF_ALU | BPF_AND | BPF_K followed by the x32 syscall ABI marker.
        self.assertTrue(any(code == 0x54 and k == 0x40000000
                            for code, _jt, _jf, k in instructions))


if __name__ == "__main__":
    unittest.main()
