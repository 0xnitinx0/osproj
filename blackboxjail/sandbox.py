"""Linux sandbox launcher, enforcement backends, output supervisor, and reports."""
from __future__ import annotations

import math
import os
from pathlib import Path
import platform
import resource
import selectors
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid
from typing import Any

from . import __version__
from .analyzer import analyze_report
from .cgroups import CgroupUnavailable, CgroupV2
from .events import EventRecorder, redact_command, utc_now
from .monitor import process_tree_metrics
from .report import save_report, state_dir
from .seccomp import build_denylist_filter, denied_syscalls

SYSTEM_DIRS = ("/usr", "/usr/local", "/bin", "/sbin", "/lib", "/lib64")
SYSTEM_ETC_PATHS = (
    "/etc/ld.so.cache", "/etc/ld.so.conf", "/etc/ld.so.conf.d",
    "/etc/ssl/certs", "/etc/alternatives", "/etc/passwd", "/etc/group",
    "/etc/nsswitch.conf", "/etc/host.conf", "/etc/hosts", "/etc/resolv.conf",
    "/etc/localtime", "/etc/ca-certificates.conf",
)
PROTECTED_WORKSPACE_ROOTS = tuple(Path(p) for p in (
    "/etc", "/usr", "/bin", "/sbin", "/lib", "/lib64", "/boot", "/dev",
    "/proc", "/sys", "/var", "/run", "/opt", "/mnt", "/media", "/snap", "/srv",
))


class SandboxError(RuntimeError):
    pass


def _add_readonly_mounts(args: list[str]) -> None:
    for source in SYSTEM_DIRS:
        if os.path.exists(source):
            args.extend(["--ro-bind", source, source])
    etc_paths = [path for path in SYSTEM_ETC_PATHS if os.path.exists(path)]
    dirs: set[str] = {"/etc"}
    for path in etc_paths:
        parent = os.path.dirname(path)
        while parent.startswith("/etc") and parent != "/etc":
            dirs.add(parent)
            parent = os.path.dirname(parent)
    for directory in sorted(dirs, key=lambda p: (p.count("/"), p)):
        args.extend(["--dir", directory])
    for source in etc_paths:
        args.extend(["--ro-bind", source, source])


def build_bwrap_command(
    command: list[str], workspace: Path, network: bool, env: dict[str, str],
    *, seccomp_fd: int | None = None, tmpfs_limit_bytes: int = 128 * 1024 * 1024,
) -> list[str]:
    bwrap = shutil.which("bwrap")
    if not bwrap:
        raise SandboxError("bubblewrap ('bwrap') is not installed. Run ./setup.sh or install bubblewrap.")
    if not command:
        raise SandboxError("No command was provided")
    # Bubblewrap normally starts the workload without capabilities for an ordinary
    # unprivileged caller. Make the intended policy explicit as well, including when
    # the launcher is invoked from a privileged development/test environment.
    args = [bwrap, "--die-with-parent", "--new-session", "--unshare-all", "--cap-drop", "ALL", "--clearenv"]
    if network:
        args.append("--share-net")
    if seccomp_fd is not None:
        args.extend(["--seccomp", str(seccomp_fd)])
    _add_readonly_mounts(args)
    args += [
        "--proc", "/proc",
        "--dev", "/dev",
        "--size", str(max(8 * 1024 * 1024, min(tmpfs_limit_bytes // 8, 64 * 1024 * 1024))),
        "--tmpfs", "/dev/shm",
        "--size", str(max(16 * 1024 * 1024, min(tmpfs_limit_bytes // 2, 256 * 1024 * 1024))),
        "--tmpfs", "/tmp",
        "--size", str(8 * 1024 * 1024),
        "--tmpfs", "/run",
        "--dir", "/home",
        "--dir", "/workspace",
        "--bind", str(workspace), "/workspace",
        "--chdir", "/workspace",
        "--setenv", "HOME", "/tmp",
        "--setenv", "USER", "sandbox",
        "--setenv", "LOGNAME", "sandbox",
        "--setenv", "SHELL", "/bin/sh",
        "--setenv", "TMPDIR", "/tmp",
        "--setenv", "PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "--setenv", "LANG", env.get("LANG", "C.UTF-8"),
        "--",
        *command,
    ]
    return args


def _preexec_limits(cpu_seconds: int, memory_bytes: int, max_open_files: int,
                    max_file_bytes: int, cgroup_path: str | None) -> None:
    """Set per-process limits and, when delegated, move launcher into its cgroup."""
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds + 1))
    resource.setrlimit(resource.RLIMIT_AS, (memory_bytes, memory_bytes))
    resource.setrlimit(resource.RLIMIT_NOFILE, (max_open_files, max_open_files))
    resource.setrlimit(resource.RLIMIT_FSIZE, (max_file_bytes, max_file_bytes))
    if hasattr(resource, "RLIMIT_MEMLOCK"):
        resource.setrlimit(resource.RLIMIT_MEMLOCK, (0, 0))
    if cgroup_path:
        # This runs after fork and before exec; every sandbox descendant inherits the
        # cgroup membership. A failure makes Popen fail, rather than silently claiming
        # that cgroup enforcement is active.
        with open(os.path.join(cgroup_path, "cgroup.procs"), "w", encoding="ascii") as handle:
            handle.write(str(os.getpid()))


def _signal_workload(proc: subprocess.Popen[bytes], cgroup: CgroupV2 | None,
                     sig: int = signal.SIGKILL) -> None:
    try:
        os.killpg(proc.pid, sig)
    except ProcessLookupError:
        pass
    if sig == signal.SIGKILL and cgroup is not None:
        cgroup.kill_all()


def _capture_text(buf: bytearray) -> str:
    return bytes(buf).decode("utf-8", errors="replace")


def execute(
    command: list[str],
    *,
    workspace: str | None = None,
    timeout_seconds: float = 15,
    cpu_seconds: int = 10,
    memory_limit_mb: int = 512,
    max_output_kb: int = 1024,
    max_processes: int = 64,
    max_open_files: int = 128,
    max_file_mb: int = 64,
    network: bool = False,
    seccomp: bool = True,
    cgroups: str = "auto",
) -> dict[str, Any]:
    if not command or not isinstance(command, list) or not all(isinstance(arg, str) for arg in command):
        raise SandboxError("Command must be a non-empty list of strings")
    if not command[0]:
        raise SandboxError("The command executable must not be empty")
    if not os.path.exists("/proc/self/stat") or not Path("/proc/self/cgroup").exists():
        raise SandboxError("BlackBoxJail currently requires Linux with /proc mounted")
    if cgroups not in ("auto", "required", "off"):
        raise SandboxError("cgroups must be 'auto', 'required', or 'off'")
    if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float)) \
            or not math.isfinite(float(timeout_seconds)) or timeout_seconds <= 0:
        raise SandboxError("Timeout must be a finite positive number")
    int_limits = {
        "cpu_seconds": cpu_seconds, "memory_limit_mb": memory_limit_mb,
        "max_output_kb": max_output_kb, "max_processes": max_processes,
        "max_open_files": max_open_files, "max_file_mb": max_file_mb,
    }
    for name, value in int_limits.items():
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise SandboxError(f"{name} must be a positive integer")
    if max_processes < 2 or max_open_files < 16:
        raise SandboxError("max_processes must be >= 2 and max_open_files must be >= 16")
    if not isinstance(network, bool) or not isinstance(seccomp, bool):
        raise SandboxError("network and seccomp options must be true or false")

    run_id = time.strftime("%Y%m%dT%H%M%S", time.gmtime()) + "Z-" + uuid.uuid4().hex[:8]
    if workspace is None:
        # Safe-by-default: untrusted code gets a dedicated workspace, not the caller's
        # current directory or home. Keep it after exit so generated output is inspectable.
        workspaces_root = state_dir() / "workspaces"
        try:
            workspaces_root.mkdir(parents=True, mode=0o700, exist_ok=True)
            workspaces_root.chmod(0o700)
        except OSError as exc:
            raise SandboxError(f"Could not create private workspace root: {exc}") from exc
        workdir = workspaces_root / run_id
        try:
            workdir.mkdir(parents=True, mode=0o700, exist_ok=False)
            workdir.chmod(0o700)
        except OSError as exc:
            raise SandboxError(f"Could not create private per-run workspace: {exc}") from exc
    else:
        workdir = Path(workspace).expanduser().resolve()
    if not workdir.is_dir():
        raise SandboxError(f"Workspace is not a directory: {workdir}")
    if workdir == Path("/"):
        raise SandboxError("Refusing to make the entire host filesystem writable as the workspace")
    home = Path.home().resolve()
    if workdir == home:
        raise SandboxError("Refusing to expose the entire home directory; choose a dedicated project subdirectory")
    protected_home_paths = tuple((home / relative).resolve() for relative in (
        ".ssh", ".gnupg", ".aws", ".azure", ".kube", ".docker",
        ".config/gcloud", ".local/share/keyrings", ".password-store",
    ))
    if any(workdir == root or root in workdir.parents for root in protected_home_paths):
        raise SandboxError(f"Refusing to expose a sensitive credential directory as writable workspace: {workdir}")
    if workdir in (Path("/home"), Path("/tmp")):
        raise SandboxError(f"Refusing to expose shared system directory {workdir}; choose a dedicated subdirectory")
    if any(workdir == root or root in workdir.parents for root in PROTECTED_WORKSPACE_ROOTS):
        raise SandboxError(f"Refusing to expose a protected system path as writable workspace: {workdir}")

    policy = {
        "timeout_seconds": timeout_seconds, "cpu_seconds": cpu_seconds,
        "memory_limit_mb": memory_limit_mb, "max_output_kb": max_output_kb,
        "max_processes": max_processes, "max_open_files": max_open_files, "max_file_mb": max_file_mb,
        "network": network, "seccomp": seccomp, "cgroups": cgroups,
    }
    memory_bytes = int(memory_limit_mb * 1024 * 1024)
    max_file_bytes = int(max_file_mb * 1024 * 1024)
    output_bytes = int(max_output_kb * 1024)
    recorder = EventRecorder(state_dir() / "events.jsonl")
    started_at = utc_now()
    start_wall = time.monotonic()
    stdout_buffer, stderr_buffer = bytearray(), bytearray()
    runtime_samples: list[dict[str, Any]] = []
    sample_dropped = 0
    peak_rss = peak_process_count = peak_observed_tree_cpu_ticks = 0
    peak_cgroup_memory = peak_cgroup_processes = 0
    max_cgroup_cpu_usec = 0
    stdout_truncated = stderr_truncated = False
    timed_out = interrupted = output_exceeded = memory_exceeded = cpu_exceeded = process_exceeded = False
    return_code: int | None = None
    cgroup: CgroupV2 | None = None
    cgroup_fallback_reason: str | None = None
    seccomp_fd_file = None
    proc: subprocess.Popen[bytes] | None = None
    selector = selectors.DefaultSelector()
    status = "launch_error"
    exit_code = 126

    safe_command = redact_command(command)
    recorder.record("run_started", run_id=run_id, command=safe_command, workspace=str(workdir), limits=policy)
    try:
        if cgroups != "off":
            try:
                cgroup = CgroupV2.create(memory_bytes, max_processes)
                recorder.record("cgroup_enforcement_enabled", run_id=run_id, path=str(cgroup.path),
                                memory_limit_bytes=memory_bytes, max_processes=max_processes)
            except CgroupUnavailable as exc:
                cgroup_fallback_reason = str(exc)
                if cgroups == "required":
                    raise SandboxError(f"Required cgroup v2 enforcement is unavailable: {exc}") from exc
                recorder.record("cgroup_fallback", run_id=run_id, reason=cgroup_fallback_reason)

        denied: list[str] = []
        if seccomp:
            try:
                filter_bytes = build_denylist_filter()
                denied = denied_syscalls()
                seccomp_fd_file = tempfile.TemporaryFile(mode="w+b")
                seccomp_fd_file.write(filter_bytes)
                seccomp_fd_file.flush()
                seccomp_fd_file.seek(0)
            except (OSError, ValueError) as exc:
                raise SandboxError(f"Could not prepare the seccomp profile: {exc}") from exc

        bwrap_command = build_bwrap_command(
            command, workdir, network, dict(os.environ),
            seccomp_fd=seccomp_fd_file.fileno() if seccomp_fd_file is not None else None,
            tmpfs_limit_bytes=memory_bytes,
        )
        pass_fds = (seccomp_fd_file.fileno(),) if seccomp_fd_file is not None else ()
        try:
            proc = subprocess.Popen(
                bwrap_command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
                close_fds=True,
                pass_fds=pass_fds,
                preexec_fn=lambda: _preexec_limits(
                    int(cpu_seconds), memory_bytes, max_open_files, max_file_bytes,
                    str(cgroup.path) if cgroup is not None else None,
                ),
                bufsize=0,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise SandboxError(f"Could not start bubblewrap: {exc}") from exc
        finally:
            if seccomp_fd_file is not None:
                seccomp_fd_file.close()
                seccomp_fd_file = None

        assert proc.stdout is not None and proc.stderr is not None
        os.set_blocking(proc.stdout.fileno(), False)
        os.set_blocking(proc.stderr.fileno(), False)
        selector.register(proc.stdout, selectors.EVENT_READ, "stdout")
        selector.register(proc.stderr, selectors.EVENT_READ, "stderr")
        recorder.record("sandbox_started", run_id=run_id, pid=proc.pid, network_enabled=network,
                        seccomp_enabled=seccomp, denied_syscalls=denied,
                        cgroup_enforced=cgroup is not None)

        end_by = start_wall + float(timeout_seconds)
        last_sample = 0.0
        post_exit_drain_deadline: float | None = None
        forced_termination = False
        while proc.poll() is None or selector.get_map():
            now = time.monotonic()
            alive_or_pipes_open = proc.poll() is None or bool(selector.get_map())
            if alive_or_pipes_open and not forced_termination and now >= end_by:
                timed_out = True
                forced_termination = True
                recorder.record("timeout", run_id=run_id, timeout_seconds=timeout_seconds)
                _signal_workload(proc, cgroup, signal.SIGTERM)
                try:
                    proc.wait(timeout=0.25)
                except subprocess.TimeoutExpired:
                    pass
                _signal_workload(proc, cgroup, signal.SIGKILL)

            # Bound pipe draining after the leader exits; a detached descendant must not
            # keep the supervisor hanging indefinitely.
            if proc.poll() is not None:
                if post_exit_drain_deadline is None:
                    post_exit_drain_deadline = now + 0.5
                elif now >= post_exit_drain_deadline and selector.get_map():
                    _signal_workload(proc, cgroup, signal.SIGKILL)
                    for key in list(selector.get_map().values()):
                        try:
                            selector.unregister(key.fileobj)
                            key.fileobj.close()
                        except (KeyError, OSError):
                            pass
                    break

            for key, _mask in selector.select(timeout=0.025):
                label = key.data
                buf = stdout_buffer if label == "stdout" else stderr_buffer
                remaining = output_bytes - len(buf)
                try:
                    chunk = os.read(key.fileobj.fileno(), max(1, min(65536, remaining + 1)))
                except BlockingIOError:
                    continue
                except OSError:
                    chunk = b""
                if not chunk:
                    try:
                        selector.unregister(key.fileobj)
                    except KeyError:
                        pass
                    key.fileobj.close()
                    continue
                if len(chunk) > remaining:
                    buf.extend(chunk[:max(0, remaining)])
                    if label == "stdout":
                        stdout_truncated = True
                    else:
                        stderr_truncated = True
                    if not output_exceeded:
                        output_exceeded = True
                        recorder.record("output_limit_exceeded", run_id=run_id, stream=label,
                                        limit_bytes=output_bytes)
                    if not forced_termination:
                        forced_termination = True
                        _signal_workload(proc, cgroup, signal.SIGTERM)
                        _signal_workload(proc, cgroup, signal.SIGKILL)
                else:
                    buf.extend(chunk)

            if proc.poll() is None and now - last_sample >= 0.1:
                sample: dict[str, Any] = {"sample_id": f"sample-{len(runtime_samples) + 1:04d}", "run_id": run_id, "elapsed_ns": int((now - start_wall) * 1_000_000_000), "timestamp_utc": utc_now()}
                if cgroup is not None:
                    cgstats = cgroup.stats()
                    peak_cgroup_memory = max(peak_cgroup_memory, cgstats["memory_peak_bytes"])
                    peak_cgroup_processes = max(peak_cgroup_processes, cgstats["processes_current"])
                    max_cgroup_cpu_usec = max(max_cgroup_cpu_usec, cgstats["cpu_usage_usec"])
                    sample.update({"source": "cgroup_v2", "rss_bytes": int(cgstats["memory_current_bytes"]), "memory_peak_bytes": int(cgstats["memory_peak_bytes"]), "process_count": int(cgstats["processes_current"]), "cpu_seconds": round(cgstats["cpu_usage_usec"] / 1_000_000, 6), "oom_kill_count": int(cgstats["oom_kill_count"])})
                    if cgstats["memory_current_bytes"] >= memory_bytes or cgstats["oom_kill_count"] > cgroup.oom_kill_start:
                        memory_exceeded = True
                        recorder.record("memory_limit_exceeded", run_id=run_id,
                                        memory_current_bytes=cgstats["memory_current_bytes"],
                                        limit_bytes=memory_bytes, oom_kill_count=cgstats["oom_kill_count"])
                        _signal_workload(proc, cgroup, signal.SIGKILL)
                        forced_termination = True
                    elif cgstats["processes_current"] > max_processes:
                        process_exceeded = True
                        recorder.record("process_limit_exceeded", run_id=run_id,
                                        processes_current=cgstats["processes_current"], limit=max_processes)
                        _signal_workload(proc, cgroup, signal.SIGKILL)
                        forced_termination = True
                    elif cgroup.cpu_accounting and cgstats["cpu_usage_usec"] > int(cpu_seconds * 1_000_000):
                        cpu_exceeded = True
                        recorder.record("cpu_limit_exceeded", run_id=run_id,
                                        cpu_usage_usec=cgstats["cpu_usage_usec"], limit_seconds=cpu_seconds)
                        _signal_workload(proc, cgroup, signal.SIGKILL)
                        forced_termination = True
                else:
                    metrics = process_tree_metrics(proc.pid)
                    peak_rss = max(peak_rss, int(metrics["rss_bytes"]))
                    peak_process_count = max(peak_process_count, int(metrics["process_count"]))
                    peak_observed_tree_cpu_ticks = max(peak_observed_tree_cpu_ticks, int(metrics["cpu_ticks"]))
                    sample.update({"source": "proc_sampled", "rss_bytes": int(metrics["rss_bytes"]), "process_count": int(metrics["process_count"]), "cpu_seconds": round(float(metrics["cpu_seconds_sampled"]), 6)})
                    if metrics["rss_bytes"] > memory_bytes and not memory_exceeded:
                        memory_exceeded = True
                        recorder.record("memory_limit_sampled_exceeded", run_id=run_id,
                                        rss_bytes=metrics["rss_bytes"], limit_bytes=memory_bytes)
                        _signal_workload(proc, cgroup, signal.SIGKILL)
                        forced_termination = True
                    elif metrics["process_count"] > max_processes and not process_exceeded:
                        process_exceeded = True
                        recorder.record("process_limit_sampled_exceeded", run_id=run_id,
                                        process_count=metrics["process_count"], limit=max_processes)
                        _signal_workload(proc, cgroup, signal.SIGKILL)
                        forced_termination = True
                if sample.get("source"):
                    if len(runtime_samples) < 2000:
                        runtime_samples.append(sample)
                    else:
                        sample_dropped += 1
                last_sample = now

        return_code = proc.wait()
        if cgroup is not None:
            final_cgstats = cgroup.stats()
            peak_cgroup_memory = max(peak_cgroup_memory, final_cgstats["memory_peak_bytes"])
            peak_cgroup_processes = max(peak_cgroup_processes, final_cgstats["processes_current"])
            max_cgroup_cpu_usec = max(max_cgroup_cpu_usec, final_cgstats["cpu_usage_usec"])
            if final_cgstats["oom_kill_count"] > cgroup.oom_kill_start or final_cgstats["memory_peak_bytes"] > memory_bytes:
                memory_exceeded = True
            if cgroup.cpu_accounting and final_cgstats["cpu_usage_usec"] > int(cpu_seconds * 1_000_000):
                cpu_exceeded = True
            pids_events = {}
            try:
                for line in (cgroup.path / "pids.events").read_text(encoding="ascii").splitlines():
                    key, value = line.split()[:2]
                    pids_events[key] = int(value)
            except (OSError, ValueError):
                pass
            if pids_events.get("max", 0) > 0:
                process_exceeded = True
                recorder.record("process_limit_exceeded", run_id=run_id,
                                pids_max_events=pids_events.get("max", 0), limit=max_processes)
            if memory_exceeded and not any(event.get("event") == "memory_limit_exceeded" for event in recorder.buffer):
                recorder.record("memory_limit_exceeded", run_id=run_id,
                                memory_peak_bytes=final_cgstats["memory_peak_bytes"], limit_bytes=memory_bytes,
                                oom_kill_count=final_cgstats["oom_kill_count"])
            if cpu_exceeded and not any(event.get("event") == "cpu_limit_exceeded" for event in recorder.buffer):
                recorder.record("cpu_limit_exceeded", run_id=run_id,
                                cpu_usage_usec=final_cgstats["cpu_usage_usec"], limit_seconds=cpu_seconds)

        # RLIMIT_CPU is per process. Map its SIGXCPU outcome into the public
        # resource-limit status instead of returning a negative signal code as an
        # apparent workload exit status.
        if return_code == -signal.SIGXCPU and not cpu_exceeded:
            cpu_exceeded = True
            recorder.record("cpu_limit_exceeded", run_id=run_id, backend="RLIMIT_CPU",
                            signal="SIGXCPU", per_process_limit_seconds=cpu_seconds)

        elapsed = time.monotonic() - start_wall
        if interrupted:
            status, exit_code = "interrupted", 130
        elif timed_out:
            status, exit_code = "timeout", 124
        elif output_exceeded:
            status, exit_code = "output_limit_exceeded", 125
        elif memory_exceeded:
            status, exit_code = "memory_limit_exceeded", 125
        elif cpu_exceeded:
            status, exit_code = "cpu_limit_exceeded", 125
        elif process_exceeded:
            status, exit_code = "process_limit_exceeded", 125
        elif return_code == -getattr(signal, "SIGXFSZ", 25):
            status, exit_code = "file_limit_exceeded", 125
            recorder.record("file_size_limit_exceeded", run_id=run_id, limit_bytes=max_file_bytes)
        elif return_code == 0:
            status, exit_code = "completed", 0
        else:
            status, exit_code = "failed", int(return_code if return_code is not None else 1)

        if status == "failed" and return_code in (-signal.SIGXCPU, -signal.SIGKILL) and cgroup is None:
            recorder.record("per_process_cpu_or_memory_limit_signal", run_id=run_id, signal=-int(return_code))
        recorder.record("run_finished", run_id=run_id, status=status, exit_code=exit_code,
                        elapsed_seconds=round(elapsed, 4))
        report = {
            "schema_version": 3,
            "blackboxjail_version": __version__,
            "run_id": run_id,
            "started_at": started_at,
            "finished_at": utc_now(),
            "duration_ms": round(elapsed * 1000, 3),
            "host": {"platform": platform.platform(), "kernel": platform.release(), "architecture": platform.machine(), "python_version": sys.version.split()[0]},
            "status": status,
            "exit_code": exit_code,
            "termination_signal": -return_code if return_code is not None and return_code < 0 else None,
            "limit_flags": {"timed_out": timed_out, "output_limit_exceeded": output_exceeded, "memory_limit_exceeded": memory_exceeded, "cpu_limit_exceeded": cpu_exceeded, "process_limit_exceeded": process_exceeded, "interrupted": interrupted},
            "command": safe_command,
            "workspace": str(workdir),
            "sandbox": {
                "backend": "bubblewrap",
                "filesystem": "selected system runtime paths read-only; isolated /tmp; workspace writable",
                "network_enabled": network,
                "namespaces": ["user", "pid", "mount", "ipc", "uts", "network (unless enabled)"],
                "seccomp_enabled": seccomp,
                "seccomp_denied_syscalls": denied,
                "cgroup_v2_enforced": cgroup is not None,
                "cgroup_cpu_accounting": bool(cgroup and cgroup.cpu_accounting),
                "cgroup_fallback_reason": cgroup_fallback_reason,
                "cgroup_path": str(cgroup.path) if cgroup is not None else None,
            },
            "limits": policy,
            "observations": {"samples": runtime_samples, "sample_interval_seconds": 0.1, "samples_dropped_by_report_cap": sample_dropped, "syscall_events": [], "file_events": [], "network_events": [], "coverage": {"resource_sampling": "enabled", "syscall_tracing": "not_enabled_in_this_version", "file_tracing": "not_enabled_in_this_version", "network_tracing": "not_enabled_in_this_version"}},
            "collection_health": {"resource_sampling": "ok", "samples_recorded": len(runtime_samples), "samples_dropped_by_report_cap": sample_dropped, "event_buffer_capacity": 512, "event_buffer_may_be_truncated": len(recorder.buffer) >= 512},
            "metrics": {
                "elapsed_seconds": round(elapsed, 4),
                "peak_rss_bytes_sampled": peak_rss,
                "peak_process_count_sampled": peak_process_count,
                "peak_cgroup_memory_bytes": peak_cgroup_memory,
                "peak_cgroup_processes": peak_cgroup_processes,
                "cgroup_cpu_seconds": round(max_cgroup_cpu_usec / 1_000_000, 4),
                "peak_observed_process_tree_cpu_seconds_snapshot": round(
                    peak_observed_tree_cpu_ticks / max(1, os.sysconf("SC_CLK_TCK")), 4),
                "stdout_bytes_captured": len(stdout_buffer),
                "stderr_bytes_captured": len(stderr_buffer),
                "stdout_truncated": stdout_truncated,
                "stderr_truncated": stderr_truncated,
            },
            "stdout": _capture_text(stdout_buffer),
            "stderr": _capture_text(stderr_buffer),
            "events": list(recorder.buffer),
        }
        analyze_report(report)
        report_path = save_report(report)
        report["report_path"] = str(report_path)
        return report
    except SandboxError as exc:
        launch_error = str(exc)
        recorder.record("launch_error", run_id=run_id, error=launch_error)
        report = {
            "schema_version": 3, "blackboxjail_version": __version__, "run_id": run_id,
            "started_at": started_at, "finished_at": utc_now(), "status": "launch_error",
            "exit_code": 126, "command": safe_command, "workspace": str(workdir),
            "limits": policy, "error": launch_error, "termination_signal": None,
            "observations": {"samples": runtime_samples, "syscall_events": [], "file_events": [], "network_events": [], "coverage": {"resource_sampling": "not_started", "syscall_tracing": "not_enabled_in_this_version", "file_tracing": "not_enabled_in_this_version", "network_tracing": "not_enabled_in_this_version"}},
            "collection_health": {"resource_sampling": "not_started", "samples_recorded": len(runtime_samples), "samples_dropped_by_report_cap": sample_dropped},
            "events": list(recorder.buffer),
        }
        analyze_report(report)
        report_path = save_report(report)
        report["report_path"] = str(report_path)
        return report
    except KeyboardInterrupt:
        interrupted = True
        if proc is not None:
            recorder.record("interrupted", run_id=run_id)
            _signal_workload(proc, cgroup, signal.SIGTERM)
            time.sleep(0.1)
            _signal_workload(proc, cgroup, signal.SIGKILL)
            try:
                proc.wait(timeout=1)
            except subprocess.TimeoutExpired:
                pass
        raise
    finally:
        try:
            selector.close()
        except Exception:
            pass
        if proc is not None:
            for stream in (proc.stdout, proc.stderr):
                if stream is not None and not stream.closed:
                    stream.close()
        if seccomp_fd_file is not None:
            seccomp_fd_file.close()
        if cgroup is not None:
            cgroup.cleanup()
