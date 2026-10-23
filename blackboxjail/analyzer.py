"""Explainable, evidence-linked black-box behaviour and failure analysis.

This module intentionally uses deterministic rules rather than ML so findings are
reproducible and straightforward to explain. It never claims to prove intent.
"""
from __future__ import annotations

from collections import Counter
from statistics import mean
from typing import Any

SCHEMA_VERSION = 1


def _event_names(report: dict[str, Any]) -> list[str]:
    return [str(e.get("event", e.get("event_type", "unknown"))) for e in report.get("events", [])]


def analyze_report(report: dict[str, Any]) -> dict[str, Any]:
    """Attach a compact behavioural fingerprint and evidence-backed findings."""
    events = report.get("events") or []
    names = _event_names(report)
    name_set = set(names)
    metrics = report.get("metrics") or {}
    limits = report.get("limits") or {}
    samples = report.get("observations", {}).get("samples", [])
    findings: list[dict[str, Any]] = []

    def add(rule_id: str, category: str, severity: str, confidence: str,
            summary: str, evidence: list[str], explanation: str,
            missing: list[str] | None = None, alternatives: list[str] | None = None) -> None:
        findings.append({
            "finding_id": f"finding-{len(findings) + 1:03d}", "rule_id": rule_id,
            "category": category, "severity": severity, "confidence": confidence,
            "summary": summary, "evidence_event_ids": evidence,
            "supporting_evidence": [explanation],
            "alternative_explanations": alternatives or [],
            "missing_evidence": missing or [],
        })

    def ids_for(*event_names: str) -> list[str]:
        wanted = set(event_names)
        return [str(e.get("event_id", e.get("event_hash", e.get("event", "event"))))
                for e in events if e.get("event") in wanted or e.get("event_type") in wanted]

    status = str(report.get("status", "unknown"))
    if status == "timeout" or "timeout" in name_set:
        add("TIME-001", "timeout", "high", "high",
            "Execution exceeded the configured wall-clock timeout.", ids_for("timeout"),
            f"Configured timeout was {limits.get('timeout_seconds', 'unknown')} seconds and the supervisor recorded a timeout.")
    if status == "memory_limit_exceeded" or any("memory_limit" in n for n in names) or "memory_oom_kill" in name_set:
        oom = "memory_oom_kill" in name_set or any(int((e.get("oom_kill_count") or 0)) > 0 for e in events)
        add("MEM-002" if oom else "MEM-001", "memory_exhaustion" if oom else "memory_pressure",
            "high" if oom or status == "memory_limit_exceeded" else "medium",
            "high" if oom or status == "memory_limit_exceeded" else "medium",
            "Memory exhaustion is supported." if oom or status == "memory_limit_exceeded" else "Memory pressure or a memory-limit threshold was observed.",
            ids_for("memory_limit_exceeded", "memory_limit_sampled_exceeded", "memory_oom_kill"),
            "A memory-limit flag or memory-related supervisor/cgroup event was recorded.",
            [] if oom else ["A matching kernel/cgroup OOM event, if available, would strengthen causal attribution."],
            ["A sampled memory threshold alone does not prove an OOM kill."] if not oom else [])
    if status == "cpu_limit_exceeded" or "cpu_limit_exceeded" in name_set:
        add("CPU-001", "cpu_limit", "high", "high", "The configured CPU limit was reported as exceeded.",
            ids_for("cpu_limit_exceeded"), f"Configured CPU budget was {limits.get('cpu_seconds', 'unknown')} seconds.")
    if status == "process_limit_exceeded" or any("process_limit" in n for n in names):
        add("PROC-001", "process_pressure", "high", "high", "The process limit was exceeded or sampled process pressure was detected.",
            ids_for("process_limit_exceeded", "process_limit_sampled_exceeded"),
            f"Configured process limit was {limits.get('max_processes', 'unknown')}.")
    if status == "output_limit_exceeded" or "output_limit_exceeded" in name_set:
        add("OUT-001", "output_limit", "medium", "high", "Captured output exceeded the configured limit.",
            ids_for("output_limit_exceeded"), f"Per-stream output cap was {limits.get('max_output_kb', 'unknown')} KiB.")
    if status == "file_limit_exceeded" or "file_size_limit_exceeded" in name_set:
        add("FILE-002", "file_size_limit", "medium", "high", "A per-file size limit was reached.",
            ids_for("file_size_limit_exceeded"), f"Per-file limit was {limits.get('max_file_mb', 'unknown')} MiB.")
    if status == "launch_error" or "launch_error" in name_set:
        add("RUN-001", "launch_failure", "high", "high", "The workload could not be launched successfully.",
            ids_for("launch_error"), str(report.get("error") or "The supervisor recorded a launch error."))
    if status == "failed":
        sig = report.get("termination_signal")
        add("CRASH-001", "unexpected_termination", "medium", "medium",
            "The workload exited unsuccessfully; root cause is not established.", ids_for("run_finished"),
            f"Exit code: {report.get('exit_code')}; termination signal: {sig if sig is not None else 'not identified'}.",
            ["A syscall trace, application diagnostics or core-dump metadata may be needed to identify root cause."],
            ["Non-zero exit can be intentional application behaviour."])
    if status == "interrupted":
        add("RUN-002", "user_interruption", "low", "high", "Execution was interrupted by the operator.",
            ids_for("interrupted"), "The supervisor recorded an interruption.")

    # Generic denied syscall evidence is only produced when a trace source actually exists.
    syscall_errors = int(metrics.get("syscall_error_count", 0) or 0)
    if syscall_errors:
        add("SYS-001", "syscall_errors", "medium", "medium", "System-call errors were observed.", [],
            f"The collector counted {syscall_errors} syscall errors.",
            ["Detailed syscall tracing may not be enabled or may have incomplete coverage."])

    if not findings and status == "completed":
        add("RUN-OK-001", "normal_completion", "info", "high", "The workload completed successfully.",
            ids_for("run_finished"), "The supervisor observed a zero exit status and no known enforced-limit outcome.")
    if not findings and status not in ("completed", "unknown"):
        add("OBS-001", "undetermined_failure", "medium", "low", "The run did not complete normally, but available evidence is insufficient to assign a specific cause.",
            ids_for("run_finished"), f"Reported status: {status}.", ["More runtime observations or syscall tracing are needed."])

    rss_values = [int(s["rss_bytes"]) for s in samples if isinstance(s, dict) and isinstance(s.get("rss_bytes"), (int, float))]
    cpu_values = [float(s["cpu_seconds"]) for s in samples if isinstance(s, dict) and isinstance(s.get("cpu_seconds"), (int, float))]
    proc_values = [int(s["process_count"]) for s in samples if isinstance(s, dict) and isinstance(s.get("process_count"), (int, float))]
    event_counts = Counter(names)
    fingerprint = {
        "version": 1,
        "workload_class": _classify(metrics, limits, status, samples),
        "runtime_seconds": metrics.get("elapsed_seconds"),
        "peak_memory_bytes": max(rss_values, default=int(metrics.get("peak_rss_bytes_sampled", 0) or metrics.get("peak_cgroup_memory_bytes", 0) or 0)),
        "mean_sampled_memory_bytes": round(mean(rss_values)) if rss_values else None,
        "peak_process_count": max(proc_values, default=int(metrics.get("peak_process_count_sampled", 0) or metrics.get("peak_cgroup_processes", 0) or 0)),
        "cpu_sample_count": len(cpu_values),
        "sample_count": len(samples),
        "event_counts": dict(sorted(event_counts.items())),
        "classification_basis": "observed metrics and supervisor events; not source-code intent",
    }
    report["analysis"] = {
        "engine_version": "1.0",
        "method": "deterministic evidence-linked rules",
        "fingerprint": fingerprint,
        "findings": findings,
        "limitations": [
            "A finding describes observed evidence and is not proof of program intent.",
            "Sampling can miss short-lived resource spikes.",
            "Complete syscall, file and network histories require additional tracing and are not implied by seccomp enforcement.",
        ],
    }
    return report


def _classify(metrics: dict[str, Any], limits: dict[str, Any], status: str, samples: list[Any]) -> str:
    if status != "completed":
        return "failed_or_limited_execution"
    peak_mem = int(metrics.get("peak_cgroup_memory_bytes", 0) or metrics.get("peak_rss_bytes_sampled", 0) or 0)
    peak_proc = int(metrics.get("peak_cgroup_processes", 0) or metrics.get("peak_process_count_sampled", 0) or 0)
    elapsed = float(metrics.get("elapsed_seconds", 0) or 0)
    cpu = float(metrics.get("cgroup_cpu_seconds", 0) or metrics.get("peak_observed_process_tree_cpu_seconds_snapshot", 0) or 0)
    mem_limit = max(1, int(limits.get("memory_limit_mb", 512)) * 1024 * 1024)
    proc_limit = max(2, int(limits.get("max_processes", 64)))
    if peak_proc >= max(8, int(proc_limit * .65)):
        return "process_heavy"
    if peak_mem >= mem_limit * .65:
        return "memory_intensive"
    if elapsed > 0 and cpu / elapsed >= .75:
        return "cpu_intensive"
    return "general_or_lightweight"
