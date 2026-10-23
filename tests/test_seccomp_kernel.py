"""Exercise the generated cBPF program against the kernel without Bubblewrap."""
import os
from pathlib import Path
import platform
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
SUPPORTED = sys.platform.startswith("linux") and platform.machine().lower() in {
    "x86_64", "amd64", "aarch64", "arm64"
}


@unittest.skipUnless(SUPPORTED, "the project seccomp profile targets Linux x86_64/aarch64")
class KernelSeccompTests(unittest.TestCase):
    def test_kernel_denies_ptrace_with_generated_filter(self):
        program = r'''
import ctypes
from blackboxjail.seccomp import build_denylist_filter
raw = build_denylist_filter()
class SockFilter(ctypes.Structure):
    _fields_ = [('code', ctypes.c_ushort), ('jt', ctypes.c_ubyte), ('jf', ctypes.c_ubyte), ('k', ctypes.c_uint32)]
class SockFprog(ctypes.Structure):
    _fields_ = [('len', ctypes.c_ushort), ('filter', ctypes.POINTER(SockFilter))]
array = (ctypes.c_ubyte * len(raw)).from_buffer_copy(raw)
program = SockFprog(len(raw) // 8, ctypes.cast(array, ctypes.POINTER(SockFilter)))
libc = ctypes.CDLL(None, use_errno=True)
if libc.prctl(38, 1, 0, 0, 0) != 0:  # PR_SET_NO_NEW_PRIVS
    raise OSError(ctypes.get_errno(), 'PR_SET_NO_NEW_PRIVS failed')
if libc.prctl(22, 2, ctypes.byref(program)) != 0:  # PR_SET_SECCOMP / FILTER
    raise OSError(ctypes.get_errno(), 'PR_SET_SECCOMP failed')
libc.ptrace.restype = ctypes.c_long
libc.ptrace.argtypes = [ctypes.c_uint, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_void_p]
result = libc.ptrace(0, 0, None, None)  # PTRACE_TRACEME
if result == -1 and ctypes.get_errno() == 1:  # EPERM from our deny rule
    print('FILTER_BLOCKED_PTRACE')
else:
    print('FILTER_FAILED', result, ctypes.get_errno())
    raise SystemExit(1)
'''
        env = dict(os.environ)
        env["PYTHONPATH"] = str(ROOT) + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
        result = subprocess.run([sys.executable, "-c", program], cwd=ROOT, env=env,
                                text=True, capture_output=True, timeout=5, check=False)
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        self.assertIn("FILTER_BLOCKED_PTRACE", result.stdout)


if __name__ == "__main__":
    unittest.main()
