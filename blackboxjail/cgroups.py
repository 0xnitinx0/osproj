"""Best-effort cgroup v2 enforcement for the sandbox workload.

The sandbox automatically falls back when the current cgroup is not delegated.
Use mode='required' to fail closed instead. It never changes permissions or
uses setuid tricks to gain control over host cgroups.
"""
from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import signal
import time
import uuid


class CgroupUnavailable(RuntimeError):
    pass


def _read_int(path: Path) -> int | None:
    try:
        return int(path.read_text(encoding="ascii").strip())
    except (OSError, ValueError):
        return None


def _read_key_values(path: Path) -> dict[str, int]:
    values: dict[str, int] = {}
    try:
        for line in path.read_text(encoding="ascii").splitlines():
            key, value = line.split()[:2]
            values[key] = int(value)
    except (OSError, ValueError):
        pass
    return values


def _current_cgroup_path() -> Path:
    try:
        rows = Path("/proc/self/cgroup").read_text(encoding="ascii").splitlines()
    except OSError as exc:
        raise CgroupUnavailable(f"cannot read /proc/self/cgroup: {exc}") from exc
    for row in rows:
        if row.startswith("0::"):
            rel = row[3:].lstrip("/")
            base = Path("/sys/fs/cgroup").resolve()
            path = (base / rel).resolve()
            if path != base and base not in path.parents:
                raise CgroupUnavailable("current cgroup path resolves outside /sys/fs/cgroup")
            return path
    raise CgroupUnavailable("unified cgroup v2 hierarchy was not found")


@dataclass
class CgroupV2:
    path: Path
    memory_limit_bytes: int
    max_processes: int
    oom_kill_start: int
    cpu_accounting: bool

    @classmethod
    def create(cls, memory_limit_bytes: int, max_processes: int) -> "CgroupV2":
        parent = _current_cgroup_path()
        if not (parent / "cgroup.controllers").is_file():
            raise CgroupUnavailable("cgroup v2 is not mounted at /sys/fs/cgroup")
        try:
            available = set((parent / "cgroup.controllers").read_text(encoding="ascii").split())
        except OSError as exc:
            raise CgroupUnavailable(f"cannot read available controllers: {exc}") from exc
        required = {"memory", "pids"}
        missing = required - available
        if missing:
            raise CgroupUnavailable("required controllers unavailable: " + ", ".join(sorted(missing)))

        try:
            control_file = parent / "cgroup.subtree_control"
            enabled = set(control_file.read_text(encoding="ascii").replace("+", "").split())
            need_enable = required - enabled
            if need_enable:
                # Requires a delegated, writable cgroup. It intentionally fails rather
                # than changing global permissions if the host has not delegated it.
                control_file.write_text(
                    " ".join("+" + controller for controller in sorted(need_enable)), encoding="ascii"
                )
            # CPU accounting is useful but optional; do not discard valid memory and
            # process controls just because the host manager did not delegate the cpu controller.
            enabled = set(control_file.read_text(encoding="ascii").replace("+", "").split())
            cpu_available = "cpu" in available
            if cpu_available and "cpu" not in enabled:
                try:
                    control_file.write_text("+cpu", encoding="ascii")
                    enabled = set(control_file.read_text(encoding="ascii").replace("+", "").split())
                except OSError:
                    pass
            cpu_accounting = "cpu" in enabled
            child = parent / f"blackboxjail-{os.getpid()}-{uuid.uuid4().hex[:8]}"
            child.mkdir(mode=0o700)
            (child / "memory.max").write_text(str(memory_limit_bytes), encoding="ascii")
            (child / "pids.max").write_text(str(max_processes), encoding="ascii")
            if (child / "memory.swap.max").exists():
                (child / "memory.swap.max").write_text("0", encoding="ascii")
            if (child / "memory.oom.group").exists():
                (child / "memory.oom.group").write_text("1", encoding="ascii")
            oom = _read_key_values(child / "memory.events").get("oom_kill", 0)
            return cls(child, memory_limit_bytes, max_processes, oom, cpu_accounting)
        except OSError as exc:
            try:
                if "child" in locals() and child.exists():
                    child.rmdir()
            except OSError:
                pass
            raise CgroupUnavailable(
                f"current cgroup is not delegated for creating/enforcing child limits: {exc}"
            ) from exc

    def attach_current_child(self) -> None:
        """Called in subprocess pre-exec, before Bubblewrap starts the workload."""
        (self.path / "cgroup.procs").write_text(str(os.getpid()), encoding="ascii")

    def stats(self) -> dict[str, int]:
        memory = _read_int(self.path / "memory.current") or 0
        memory_peak = _read_int(self.path / "memory.peak")
        processes = _read_int(self.path / "pids.current") or 0
        cpu = _read_key_values(self.path / "cpu.stat").get("usage_usec", 0)
        events = _read_key_values(self.path / "memory.events")
        return {
            "memory_current_bytes": memory,
            "memory_peak_bytes": memory_peak if memory_peak is not None else memory,
            "processes_current": processes,
            "cpu_usage_usec": cpu if self.cpu_accounting else 0,
            "oom_kill_count": events.get("oom_kill", 0),
        }

    def kill_all(self) -> None:
        kill_file = self.path / "cgroup.kill"
        try:
            kill_file.write_text("1", encoding="ascii")
            return
        except OSError:
            pass
        # Older cgroup v2 kernels lack cgroup.kill. Iterate more than once in case
        # a process forks while the fallback signal is being delivered.
        for _ in range(3):
            try:
                pids = [int(p) for p in (self.path / "cgroup.procs").read_text().split()]
            except (OSError, ValueError):
                return
            if not pids:
                return
            for pid in pids:
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            time.sleep(0.01)

    def cleanup(self) -> None:
        self.kill_all()
        try:
            self.path.rmdir()
        except OSError:
            # A busy cgroup is a warning at the caller; never recursively manipulate
            # the host cgroup hierarchy.
            pass
