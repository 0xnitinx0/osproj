"""Bounded, reproducible behavior checks for real sandbox features."""
from __future__ import annotations

import json
import os
from pathlib import Path
import platform
import socket
import sys
import tempfile
import time
import uuid
from typing import Any

from . import __version__
from .events import utc_now
from .report import state_dir
from .sandbox import execute


def run_benchmarks(*, cgroups: str = "auto", memory_limit_mb: int = 128,
                   output_kb: int = 4) -> dict[str, Any]:
    """Validate selected controls with safe, bounded workloads.

    This is a feature-validation suite, not a throughput benchmark. It avoids
    uncontrolled fork bombs and unbounded host memory or disk exhaustion.
    """
    started_at = utc_now()
    suite_id = time.strftime("%Y%m%dT%H%M%S", time.gmtime()) + "Z-" + uuid.uuid4().hex[:8]
    suite_started = time.monotonic()
    scenarios: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="bbj-bench-") as root:
        root_path = Path(root)
        # A host-only listener gives the isolated network namespace a concrete,
        # deterministic reachability target without contacting the public internet.
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as host_listener:
            host_listener.bind(("127.0.0.1", 0))
            host_listener.listen(1)
            host_port = host_listener.getsockname()[1]

            jobs = [
                {
                    "name": "baseline_execution",
                    "command": ["/bin/sh", "-c", "printf 'baseline-ok\\n'"],
                    "expected": "completed", "timeout_seconds": 3, "cpu_seconds": 2,
                    "memory_limit_mb": memory_limit_mb, "max_output_kb": output_kb,
                },
                {
                    "name": "wall_clock_timeout",
                    "command": ["/bin/sleep", "2"],
                    "expected": "timeout", "timeout_seconds": 0.35, "cpu_seconds": 2,
                    "memory_limit_mb": memory_limit_mb, "max_output_kb": output_kb,
                },
                {
                    "name": "output_flood_is_capped",
                    "command": ["/usr/bin/yes", "blackboxjail"],
                    "expected": "output_limit_exceeded", "timeout_seconds": 3, "cpu_seconds": 2,
                    "memory_limit_mb": memory_limit_mb, "max_output_kb": output_kb,
                },
                {
                    "name": "seccomp_denies_ptrace",
                    "command": [sys.executable, "-c",
                                "import ctypes; c=ctypes.CDLL(None,use_errno=True); "
                                "r=c.ptrace(0,0,None,None); "
                                "print('BLOCKED' if r == -1 and ctypes.get_errno() == 1 else 'UNEXPECTED')"],
                    "expected": "completed", "timeout_seconds": 4, "cpu_seconds": 2,
                    "memory_limit_mb": memory_limit_mb, "max_output_kb": output_kb,
                },
                {
                    "name": "workspace_write_is_explicit",
                    "command": ["/bin/sh", "-c", "printf 'workspace-write-ok' > /workspace/.bbj-benchmark-check"],
                    "expected": "completed", "timeout_seconds": 3, "cpu_seconds": 2,
                    "memory_limit_mb": memory_limit_mb, "max_output_kb": output_kb,
                },
                {
                    "name": "network_isolation_default",
                    "command": [sys.executable, "-c", """import socket, sys
s = None
try:
    s = socket.socket()
    s.settimeout(0.4)
    s.connect(("127.0.0.1", int(sys.argv[1])))
    print("NETWORK_REACHABLE")
except OSError:
    # Includes seccomp fallback rejecting socket creation before connect().
    print("NETWORK_ISOLATED")
finally:
    if s is not None:
        s.close()
""", str(host_port)],
                    "expected": "completed", "timeout_seconds": 3, "cpu_seconds": 2,
                    "memory_limit_mb": memory_limit_mb, "max_output_kb": output_kb,
                },
                {
                    "name": "per_file_limit_is_kernel_enforced",
                    "command": [sys.executable, "-c", """import errno
path = "/workspace/big.bin"
try:
    with open(path, "wb") as stream:
        stream.write(b"x" * (2 * 1024 * 1024))
        stream.flush()
    print("UNEXPECTED")
except OSError as exc:
    print("BLOCKED" if exc.errno == errno.EFBIG else "ERROR")
"""],
                    "expected": "completed", "timeout_seconds": 3, "cpu_seconds": 2,
                    "memory_limit_mb": memory_limit_mb, "max_output_kb": output_kb,
                },
                {
                    "name": "process_limit_is_observed",
                    "command": [sys.executable, "-c",
                                "import subprocess; ps=[subprocess.Popen(['/bin/sleep','1.5']) "
                                "for _ in range(12)]; [p.wait() for p in ps]"],
                    "expected": "process_limit_exceeded", "timeout_seconds": 4, "cpu_seconds": 3,
                    "memory_limit_mb": memory_limit_mb, "max_output_kb": output_kb,
                },
                {
                    "name": "address_space_limit_is_enforced",
                    "command": [sys.executable, "-c", """try:
    payload = bytearray(256 * 1024 * 1024)
    payload[0] = 1
    print("UNEXPECTED")
except MemoryError:
    print("MEMORY_LIMIT_HIT")
"""],
                    "expected": "completed or memory_limit_exceeded", "timeout_seconds": 3, "cpu_seconds": 2,
                    "memory_limit_mb": 64, "max_output_kb": output_kb,
                },
            ]

            for index, job in enumerate(jobs):
                workspace = root_path / f"case-{index}"
                workspace.mkdir()
                started = time.monotonic()
                per_case_process_limit = 4 if job["name"] == "process_limit_is_observed" else 32
                per_case_file_limit = 1 if job["name"] == "per_file_limit_is_kernel_enforced" else 64
                result = execute(
                    job["command"], workspace=str(workspace), timeout_seconds=job["timeout_seconds"],
                    cpu_seconds=job["cpu_seconds"], memory_limit_mb=job["memory_limit_mb"],
                    max_output_kb=job["max_output_kb"], max_processes=per_case_process_limit,
                    max_open_files=64, max_file_mb=per_case_file_limit,
                    network=False, seccomp=True, cgroups=cgroups,
                )
                elapsed = time.monotonic() - started
                status = result["status"]
                stdout = result.get("stdout", "")
                passed = status == job["expected"]
                note = stdout.strip()

                name = job["name"]
                if name == "seccomp_denies_ptrace":
                    passed = status == "completed" and "BLOCKED" in stdout
                elif name == "workspace_write_is_explicit":
                    target = workspace / ".bbj-benchmark-check"
                    passed = status == "completed" and target.exists() and target.read_text() == "workspace-write-ok"
                    note = "write confined to selected workspace" if passed else "expected workspace file was not created"
                elif name == "network_isolation_default":
                    passed = status == "completed" and "NETWORK_ISOLATED" in stdout
                    note = stdout.strip() or "No probe result was produced"
                elif name == "per_file_limit_is_kernel_enforced":
                    target = workspace / "big.bin"
                    passed = (status == "completed" and "BLOCKED" in stdout
                              and (not target.exists() or target.stat().st_size <= 1024 * 1024))
                    note = stdout.strip() or "The file-size probe produced no confirmation"
                elif name == "process_limit_is_observed":
                    passed = status == "process_limit_exceeded"
                    if not note:
                        note = "process/task ceiling was observed and workload stopped" if passed else f"actual status: {status}"
                elif name == "address_space_limit_is_enforced":
                    # With cgroup OOM-group semantics, the kernel may kill the workload
                    # before Python can print its MemoryError marker. Both outcomes are
                    # valid evidence, but only the report distinguishes the mechanisms.
                    passed = (status == "completed" and "MEMORY_LIMIT_HIT" in stdout) or status == "memory_limit_exceeded"
                    if not note:
                        note = f"kernel/cgroup enforcement outcome: {status}"
                elif name == "output_flood_is_capped":
                    metrics = result.get("metrics", {})
                    passed = status == "output_limit_exceeded" and metrics.get("stdout_bytes_captured", 0) <= output_kb * 1024
                    note = f"captured {metrics.get('stdout_bytes_captured', 0)} bytes"
                elif name == "wall_clock_timeout":
                    passed = status == "timeout"
                    note = f"stopped after {result.get('metrics', {}).get('elapsed_seconds', elapsed):.3f}s"

                scenarios.append({
                    "name": name, "passed": bool(passed),
                    "expected_status": job["expected"], "actual_status": status,
                    "exit_code": result["exit_code"], "elapsed_seconds": round(elapsed, 4),
                    "note": note, "report_path": result.get("report_path"),
                    "cgroup_v2_enforced": result.get("sandbox", {}).get("cgroup_v2_enforced", False),
                    "cgroup_cpu_accounting": result.get("sandbox", {}).get("cgroup_cpu_accounting", False),
                    "network_isolation_method": result.get("sandbox", {}).get("network_isolation_method", "unknown"),
                })

    return {
        "schema_version": 1,
        "suite_id": suite_id,
        "suite": "BlackBoxJail bounded feature validation",
        "version": __version__,
        "started_at": started_at,
        "finished_at": utc_now(),
        "elapsed_seconds": round(time.monotonic() - suite_started, 4),
        "environment": {
            "platform": sys.platform,
            "kernel_release": platform.release(),
            "machine": platform.machine(),
            "python_version": platform.python_version(),
        },
        "configuration": {
            "cgroups": cgroups,
            "memory_limit_mb": memory_limit_mb,
            "output_kb": output_kb,
        },
        "passed": sum(1 for item in scenarios if item["passed"]),
        "total": len(scenarios),
        "all_passed": all(item["passed"] for item in scenarios),
        "scenarios": scenarios,
    }


def save_benchmark_report(report: dict[str, Any]) -> Path:
    """Persist the complete suite result with owner-only permissions."""
    directory = state_dir() / "benchmarks"
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    directory.chmod(0o700)
    path = directory / f"{report['suite_id']}.json"
    temporary = path.with_suffix(".json.tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            os.fchmod(handle.fileno(), 0o600)
            json.dump(report, handle, indent=2, ensure_ascii=False, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(path)
        os.chmod(path, 0o600)
    except Exception:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        raise
    return path


def print_benchmarks(*, cgroups: str = "auto", memory_limit_mb: int = 128,
                     output_kb: int = 4) -> int:
    try:
        report = run_benchmarks(cgroups=cgroups, memory_limit_mb=memory_limit_mb, output_kb=output_kb)
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"Benchmark could not run: {exc}", file=sys.stderr)
        return 1
    for scenario in report["scenarios"]:
        marker = "PASS" if scenario["passed"] else "FAIL"
        print(f"[{marker}] {scenario['name']}: {scenario['actual_status']} — {scenario['note']}")
    print(f"\nFeature validation: {report['passed']}/{report['total']} passed")
    try:
        report_path = save_benchmark_report(report)
    except OSError as exc:
        print(f"Warning: could not save benchmark suite summary: {exc}", file=sys.stderr)
    else:
        print(f"Suite evidence: {report_path}")
    print("Individual execution reports are saved under the same state directory's reports/ folder.")
    return 0 if report["all_passed"] else 1
