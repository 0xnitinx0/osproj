"""Native-versus-sandboxed launch overhead measurements for known-safe workloads."""
from __future__ import annotations

import math
import statistics
import subprocess
import sys
import time
from typing import Any

from . import __version__
from .sandbox import SandboxError, execute


def _percentile95(values: list[float]) -> float:
    """Nearest-rank p95, deterministic for the small sample sets used here."""
    ordered = sorted(values)
    index = max(0, math.ceil(0.95 * len(ordered)) - 1)
    return ordered[index]


def _summary(values: list[float]) -> dict[str, float]:
    if not values:
        raise ValueError("at least one timing sample is required")
    return {
        "samples": len(values),
        "median_ms": round(statistics.median(values) * 1000, 3),
        "p95_ms": round(_percentile95(values) * 1000, 3),
        "min_ms": round(min(values) * 1000, 3),
        "max_ms": round(max(values) * 1000, 3),
    }


def run_overhead_measurement(*, iterations: int = 10, cgroups: str = "off") -> dict[str, Any]:
    """Measure native and sandboxed timings for fixed, bounded, trusted commands.

    Arbitrary commands are intentionally not accepted: each native workload runs
    outside the sandbox, so this feature only executes fixed, harmless probes.
    Timings include process launch, and sandbox timings include namespace and
    supervisor setup, making them useful as end-to-end launch-overhead estimates.
    """
    if isinstance(iterations, bool) or not isinstance(iterations, int) or not 3 <= iterations <= 100:
        raise ValueError("iterations must be an integer between 3 and 100")
    if cgroups not in ("auto", "required", "off"):
        raise ValueError("cgroups must be 'auto', 'required', or 'off'")

    workloads: list[tuple[str, list[str]]] = [
        ("tiny_native_binary", ["/bin/true"]),
        ("python_startup", [sys.executable, "-c", "pass"]),
        ("small_cpu_work", [sys.executable, "-c", "sum(i*i for i in range(50000))"]),
    ]
    results: list[dict[str, Any]] = []
    for name, command in workloads:
        native_samples: list[float] = []
        sandbox_samples: list[float] = []
        for index in range(iterations):
            # Alternate order to reduce consistent warm-up/order bias.
            modes = ("native", "sandbox") if index % 2 == 0 else ("sandbox", "native")
            for mode in modes:
                if mode == "native":
                    started = time.monotonic()
                    completed = subprocess.run(
                        command, stdin=subprocess.DEVNULL,
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                        timeout=10, check=False,
                    )
                    elapsed = time.monotonic() - started
                    if completed.returncode != 0:
                        raise RuntimeError(f"native probe {name} exited with code {completed.returncode}")
                    native_samples.append(elapsed)
                else:
                    report = execute(
                        command, timeout_seconds=10, cpu_seconds=5,
                        memory_limit_mb=256, max_output_kb=16,
                        max_processes=32, max_open_files=64, max_file_mb=16,
                        network=False, seccomp=True, cgroups=cgroups,
                    )
                    if report.get("status") != "completed":
                        raise RuntimeError(
                            f"sandbox probe {name} did not complete: {report.get('status')} "
                            f"({report.get('error', 'no additional error detail')})"
                        )
                    sandbox_samples.append(float(report["metrics"]["elapsed_seconds"]))

        native_stats = _summary(native_samples)
        sandbox_stats = _summary(sandbox_samples)
        native_median = native_stats["median_ms"]
        sandbox_median = sandbox_stats["median_ms"]
        results.append({
            "workload": name,
            "command": command,
            "native": native_stats,
            "sandboxed": sandbox_stats,
            "median_overhead_ms": round(sandbox_median - native_median, 3),
            "median_slowdown_percent": round((sandbox_median / native_median - 1) * 100, 2)
                if native_median > 0 else None,
            "median_slowdown_factor": round(sandbox_median / native_median, 2)
                if native_median > 0 else None,
        })

    return {
        "suite": "BlackBoxJail native versus sandbox launch overhead",
        "version": __version__,
        "iterations_per_mode": iterations,
        "cgroups_mode": cgroups,
        "metric_scope": "end-to-end process launch and sandbox supervision; not a syscall microbenchmark",
        "notes": [
            "Native and sandboxed modes are run in alternating order to reduce ordering bias.",
            "Use repeated runs on an otherwise idle machine; CPU scaling and filesystem cache affect results.",
            "Sandboxed timing includes namespace, policy, supervisor and event-recording overhead.",
            "This command uses only fixed, harmless workloads and does not accept arbitrary commands.",
        ],
        "workloads": results,
    }


def print_overhead_measurement(*, iterations: int = 10, cgroups: str = "off") -> int:
    import json

    try:
        report = run_overhead_measurement(iterations=iterations, cgroups=cgroups)
    except (OSError, subprocess.SubprocessError, SandboxError, RuntimeError, ValueError) as exc:
        print(f"Measurement failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2))
    return 0
