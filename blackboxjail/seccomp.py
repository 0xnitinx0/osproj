"""Generate a small architecture-checked classic-BPF seccomp deny-list.

Bubblewrap consumes the compiled sock_filter stream using --seccomp FD.  This
is deliberately a deny-list for dangerous kernel interfaces, not a claim that
all other syscalls are safe or that seccomp alone forms a complete sandbox.
"""
from __future__ import annotations

import platform
import struct

# classic BPF opcodes / seccomp return actions
BPF_LD_W_ABS = 0x20
BPF_JMP_JEQ_K = 0x15
BPF_ALU_AND_K = 0x54
BPF_RET_K = 0x06
SECCOMP_RET_KILL_PROCESS = 0x80000000
SECCOMP_RET_ERRNO = 0x00050000
SECCOMP_RET_ALLOW = 0x7FFF0000
EPERM = 1

ARCHITECTURES: dict[str, tuple[int, dict[str, int]]] = {
    "x86_64": (0xC000003E, {
        "ptrace": 101, "mount": 165, "umount2": 166, "pivot_root": 155,
        "reboot": 169, "init_module": 175, "delete_module": 176,
        "kexec_load": 246, "kexec_file_load": 320,
        "mknod": 133, "mknodat": 259, "swapon": 167, "swapoff": 168,
        "add_key": 248, "request_key": 249, "keyctl": 250,
        "perf_event_open": 298, "name_to_handle_at": 303, "open_by_handle_at": 304,
        "process_vm_readv": 310, "process_vm_writev": 311, "setns": 308,
        "unshare": 272, "bpf": 321, "userfaultfd": 323,
        "finit_module": 313, "io_uring_setup": 425, "io_uring_enter": 426,
        "io_uring_register": 427, "open_tree": 428, "move_mount": 429,
        "fsopen": 430, "fsconfig": 431, "fsmount": 432, "fspick": 433,
        "pidfd_getfd": 438, "mount_setattr": 442,
    }),
    "aarch64": (0xC00000B7, {
        "ptrace": 117, "mount": 40, "umount2": 39, "pivot_root": 41,
        "reboot": 142, "init_module": 105, "delete_module": 106,
        "kexec_load": 104, "kexec_file_load": 294,
        "mknod": 33, "mknodat": 33, "swapon": 224, "swapoff": 225,
        "add_key": 217, "request_key": 218, "keyctl": 219,
        "perf_event_open": 241, "name_to_handle_at": 264, "open_by_handle_at": 265,
        "process_vm_readv": 270, "process_vm_writev": 271, "setns": 268,
        "unshare": 97, "bpf": 280, "userfaultfd": 282,
        "finit_module": 273, "io_uring_setup": 425, "io_uring_enter": 426,
        "io_uring_register": 427, "open_tree": 428, "move_mount": 429,
        "fsopen": 430, "fsconfig": 431, "fsmount": 432, "fspick": 433,
        "pidfd_getfd": 438, "mount_setattr": 442,
    }),
}


# Network syscalls denied when a restricted host cannot create a network
# namespace. This fallback is weaker than a dedicated net namespace, so reports
# name it explicitly rather than claiming namespace isolation.
NETWORK_SYSCALLS: dict[str, dict[str, int]] = {
    "x86_64": {
        "socket": 41, "connect": 42, "accept": 43, "sendto": 44,
        "recvfrom": 45, "sendmsg": 46, "recvmsg": 47, "shutdown": 48,
        "bind": 49, "listen": 50, "getsockname": 51, "getpeername": 52,
        "socketpair": 53, "setsockopt": 54, "getsockopt": 55,
        "accept4": 288, "recvmmsg": 299, "sendmmsg": 307,
        # io_uring has socket/create/connect/accept/send/receive operations too.
        "io_uring_setup": 425, "io_uring_enter": 426, "io_uring_register": 427,
    },
    "aarch64": {
        "socket": 198, "socketpair": 199, "bind": 200, "listen": 201,
        "accept": 202, "connect": 203, "getsockname": 204, "getpeername": 205,
        "sendto": 206, "recvfrom": 207, "setsockopt": 208, "getsockopt": 209,
        "shutdown": 210, "sendmsg": 211, "recvmsg": 212,
        "accept4": 242, "recvmmsg": 243, "sendmmsg": 269,
        "io_uring_setup": 425, "io_uring_enter": 426, "io_uring_register": 427,
    },
}

# Each instruction is struct sock_filter: u16 code, u8 jt, u8 jf, u32 k.
def _insn(code: int, jt: int = 0, jf: int = 0, k: int = 0) -> bytes:
    return struct.pack("=HBBI", code, jt, jf, k)


def current_architecture() -> str:
    machine = platform.machine().lower()
    aliases = {"amd64": "x86_64", "arm64": "aarch64"}
    machine = aliases.get(machine, machine)
    if machine not in ARCHITECTURES:
        raise ValueError(f"seccomp profile is not defined for architecture {machine!r}")
    return machine


def build_denylist_filter(*, include_default: bool = True, block_network: bool = False) -> bytes:
    """Return an architecture-checked cBPF filter.

    ``block_network`` adds socket and socket-operation denials for hosts where
    Bubblewrap cannot configure a network namespace. This fallback intentionally
    blocks all new network socket operations (including AF_UNIX socketpair) and
    is reported separately from network-namespace isolation.
    """
    architecture = current_architecture()
    audit_arch, default_syscalls = ARCHITECTURES[architecture]
    syscalls = dict(default_syscalls) if include_default else {}
    if block_network:
        syscalls.update(NETWORK_SYSCALLS[architecture])
    program = bytearray()
    # seccomp_data.arch lives at byte offset 4.  On a mismatch, kill the process.
    program += _insn(BPF_LD_W_ABS, k=4)
    program += _insn(BPF_JMP_JEQ_K, jt=1, jf=0, k=audit_arch)
    program += _insn(BPF_RET_K, k=SECCOMP_RET_KILL_PROCESS)
    # Reject the x32 ABI on x86-64. x32 syscall numbers OR in 0x40000000;
    # checking only native syscall numbers would leave a compatibility-ABI gap.
    if architecture == "x86_64":
        program += _insn(BPF_LD_W_ABS, k=0)
        program += _insn(BPF_ALU_AND_K, k=0x40000000)
        program += _insn(BPF_JMP_JEQ_K, jt=0, jf=1, k=0x40000000)
        program += _insn(BPF_RET_K, k=SECCOMP_RET_KILL_PROCESS)
    # syscall number is at offset 0.
    program += _insn(BPF_LD_W_ABS, k=0)
    for number in sorted(set(syscalls.values())):
        program += _insn(BPF_JMP_JEQ_K, jt=0, jf=1, k=number)
        program += _insn(BPF_RET_K, k=SECCOMP_RET_ERRNO | EPERM)
    program += _insn(BPF_RET_K, k=SECCOMP_RET_ALLOW)
    return bytes(program)


def denied_syscalls(*, include_default: bool = True, block_network: bool = False) -> list[str]:
    """Return syscall names denied by the requested filter profile."""
    architecture = current_architecture()
    names = set(ARCHITECTURES[architecture][1]) if include_default else set()
    if block_network:
        names.update(NETWORK_SYSCALLS[architecture])
    return sorted(names)
