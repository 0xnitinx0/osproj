"""Command-line interface for BlackBoxJail."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil
import sys
import tempfile
from typing import Any

from . import __version__
from .audit import verify_journal
from .benchmark import print_benchmarks
from .measure import print_overhead_measurement
from .policy import DEFAULT_POLICY, load_policy
from .report import list_reports, state_dir
from .sandbox import SandboxError, execute
from .seccomp import current_architecture, denied_syscalls


def _size(value: int | float) -> str:
    value = float(value)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if value < 1024 or unit == "GiB":
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} B"


def cmd_doctor(self_test: bool = False) -> int:
    print(f"BlackBoxJail {__version__} — environment check")
    checks: list[tuple[str, bool, str]] = [
        ("Linux kernel", sys.platform.startswith("linux"), sys.platform),
        ("Python >= 3.10", sys.version_info >= (3, 10), sys.version.split()[0]),
        ("bubblewrap", shutil.which("bwrap") is not None, shutil.which("bwrap") or "not found"),
        ("/proc filesystem", Path("/proc/self/stat").exists(), "process metrics source"),
        ("cgroup v2 mount", Path("/sys/fs/cgroup/cgroup.controllers").exists(),
         "mounted" if Path("/sys/fs/cgroup/cgroup.controllers").exists() else "not detected; auto mode can fall back"),
    ]
    try:
        arch = current_architecture()
        seccomp_detail = f"{arch}; {len(denied_syscalls())} syscall deny rules"
        seccomp_ok = True
    except ValueError as exc:
        seccomp_detail, seccomp_ok = str(exc), False
    checks.append(("seccomp profile", seccomp_ok, seccomp_detail))
    for name, ok, detail in checks:
        # cgroup mount is informative but a missing delegation is not an environment failure
        if name == "cgroup v2 mount":
            print(f"[INFO] {name}: {detail}")
        else:
            print(f"[{'OK' if ok else 'MISSING'}] {name}: {detail}")

    required = [ok for name, ok, _ in checks if name != "cgroup v2 mount"]
    if not all(required):
        print("\nInstall missing requirements; on Ubuntu/Debian: sudo apt install python3 bubblewrap")
        return 1
    if self_test:
        print("\nRunning a real sandbox smoke test (with seccomp enabled)...")
        result = execute(
            ["/bin/echo", "BlackBoxJail sandbox is working"],
            timeout_seconds=3, cpu_seconds=2, memory_limit_mb=128, max_output_kb=16,
            max_processes=16, max_open_files=64, network=False, seccomp=True, cgroups="auto",
        )
        print(f"[{result['status'].upper()}] {result.get('stdout', '').strip()}")
        backend = result.get("sandbox", {})
        if backend.get("cgroup_v2_enforced"):
            if backend.get("cgroup_cpu_accounting"):
                print("[OK] cgroup v2 hard memory/task caps and aggregate CPU accounting active")
            else:
                print("[OK] cgroup v2 hard memory/task caps active; CPU controller is not delegated")
        elif result.get("events"):
            reasons = [event.get("reason") for event in result["events"] if event.get("event") == "cgroup_fallback"]
            print("[INFO] cgroup v2 not delegated; using per-process limits plus sampled process-tree RSS")
            if reasons:
                print(f"       Reason: {reasons[-1]}")
        if result.get("report_path"):
            print(f"Report: {result['report_path']}")
        if result["status"] != "completed":
            if result.get("error"):
                print(f"Reason: {result['error']}")
            print("Check user namespaces and Bubblewrap permissions for this Linux distribution.")
            return 1
    else:
        print(f"\nState directory: {state_dir()}")
        print("Run './bbj doctor --self-test' to verify sandbox launch and seccomp application.")
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    try:
        policy = load_policy(args.policy)
    except ValueError as exc:
        print(f"Policy error: {exc}", file=sys.stderr)
        return 2

    command = list(args.command)
    if command and command[0] == "--":
        command.pop(0)
    if not command:
        print("Error: provide a command after '--'. Example: ./bbj run -- /bin/echo hello", file=sys.stderr)
        return 2

    overrides: dict[str, Any] = {
        "workspace": args.workspace,
        "timeout_seconds": args.timeout if args.timeout is not None else policy["timeout_seconds"],
        "cpu_seconds": args.cpu_seconds if args.cpu_seconds is not None else policy["cpu_seconds"],
        "memory_limit_mb": args.memory_mb if args.memory_mb is not None else policy["memory_limit_mb"],
        "max_output_kb": args.max_output_kb if args.max_output_kb is not None else policy["max_output_kb"],
        "max_processes": args.max_processes if args.max_processes is not None else policy["max_processes"],
        "max_open_files": args.max_open_files if args.max_open_files is not None else policy["max_open_files"],
        "max_file_mb": args.max_file_mb if args.max_file_mb is not None else policy["max_file_mb"],
        "network": policy["network"] if args.network is None else args.network,
        "seccomp": False if args.no_seccomp else policy["seccomp"],
        "cgroups": args.cgroups if args.cgroups is not None else policy["cgroups"],
    }

    print(f"BlackBoxJail: running {' '.join(command)}")
    if args.workspace is None:
        print("Workspace: dedicated per-run directory (safe default; see report for its path)")
    else:
        print(f"Workspace (writable by workload): {Path(args.workspace).expanduser().resolve()}")
    print("Network: enabled" if overrides["network"] else "Network: disabled (isolated network namespace)")
    print(f"Enforcement: seccomp={'on' if overrides['seccomp'] else 'OFF'}; cgroups={overrides['cgroups']}; "
          f"{overrides['max_processes']} processes; {overrides['max_open_files']} open files")
    print(f"Limits: {overrides['timeout_seconds']}s wall time, {overrides['cpu_seconds']}s CPU budget, "
          f"{overrides['memory_limit_mb']} MiB memory, {overrides['max_output_kb']} KiB per output stream, "
          f"{overrides['max_file_mb']} MiB per file")
    try:
        result = execute(command, **overrides)
    except SandboxError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 126

    if result.get("stdout"):
        sys.stdout.write(result["stdout"])
        if not result["stdout"].endswith("\n"):
            sys.stdout.write("\n")
    if result.get("stderr"):
        sys.stderr.write(result["stderr"])
        if not result["stderr"].endswith("\n"):
            sys.stderr.write("\n")

    print(f"\nResult: {result['status']} (exit {result['exit_code']})")
    metrics = result.get("metrics", {})
    if metrics:
        if result.get("sandbox", {}).get("cgroup_v2_enforced"):
            line = (f"Elapsed: {metrics.get('elapsed_seconds', 0):.3f}s | "
                    f"Peak cgroup memory: {_size(metrics.get('peak_cgroup_memory_bytes', 0))} | "
                    f"Peak cgroup tasks observed: {metrics.get('peak_cgroup_processes', 0)}")
            if result.get("sandbox", {}).get("cgroup_cpu_accounting"):
                line += f" | Aggregate CPU: {metrics.get('cgroup_cpu_seconds', 0):.3f}s"
            print(line)
        else:
            print(f"Elapsed: {metrics.get('elapsed_seconds', 0):.3f}s | "
                  f"Peak sampled process-tree RSS: {_size(metrics.get('peak_rss_bytes_sampled', 0))} | "
                  f"Peak observed processes: {metrics.get('peak_process_count_sampled', 0)}")
    sandbox_info = result.get("sandbox", {})
    if sandbox_info.get("cgroup_fallback_reason"):
        print(f"Cgroup fallback: {sandbox_info['cgroup_fallback_reason']}")
    if result.get("error"):
        print(f"Error: {result['error']}", file=sys.stderr)
    if result.get("report_path"):
        print(f"Report: {result['report_path']}")
    return int(result["exit_code"])


def cmd_report(args: argparse.Namespace) -> int:
    paths = list_reports()
    if not paths:
        print("No reports yet. Run a command with './bbj run -- <command>'.")
        return 0
    if args.latest:
        path = paths[0]
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            print(f"Could not read report {path}: {exc}", file=sys.stderr)
            return 1
        print(json.dumps(data, indent=2, ensure_ascii=False))
        return 0
    for path in paths[: args.limit]:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        print(f"{data.get('run_id', path.stem)}  {data.get('status', 'unknown'):24} "
              f"exit={data.get('exit_code', '?')}  {' '.join(data.get('command', []))}")
        print(f"  {path}")
    return 0



def cmd_inspect(args: argparse.Namespace) -> int:
    """Display the complete stored report in readable sections or raw JSON."""
    paths = list_reports()
    if not paths:
        print("No reports yet. Run './bbj run -- <command>' first.")
        return 0
    selected: Path | None = None
    if args.run_id:
        for candidate in paths:
            if candidate.stem == args.run_id:
                selected = candidate
                break
        if selected is None:
            print(f"No report found for run ID: {args.run_id}", file=sys.stderr)
            return 1
    else:
        selected = paths[0]
    try:
        report = json.loads(selected.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"Could not read report {selected}: {exc}", file=sys.stderr)
        return 1
    if args.raw:
        print(json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True))
        return 0

    print("BLACKBOXJAIL — COMPLETE RUN INSPECTION")
    print("=" * 42)
    print(f"Run ID: {report.get('run_id', selected.stem)}")
    print(f"Status: {report.get('status', 'unknown')} | exit={report.get('exit_code', '?')} | duration={report.get('duration_ms', 'unknown')} ms")
    print(f"Started: {report.get('started_at', 'unknown')} | Finished: {report.get('finished_at', 'unknown')}")
    for section, key in [
        ("HOST", "host"), ("COMMAND AND CONFIGURATION", "command"),
        ("WORKSPACE", "workspace"), ("LIMITS", "limits"),
        ("SANDBOX / ENFORCEMENT", "sandbox"), ("EXECUTION OUTCOME", "outcome"),
        ("METRICS", "metrics"), ("COLLECTION HEALTH", "collection_health"),
        ("OBSERVATION COVERAGE", "observations"), ("BEHAVIOURAL ANALYSIS", "analysis"),
        ("STANDARD OUTPUT", "stdout"), ("STANDARD ERROR", "stderr"), ("ERROR", "error"),
        ("RECORDED EVENTS", "events"),
    ]:
        if key == "outcome":
            data = {name: report.get(name) for name in ("status", "exit_code", "termination_signal", "error") if name in report}
        else:
            data = report.get(key)
        if data is None or data == "" or data == [] or data == {}:
            continue
        print(f"\n[{section}]")
        if key == "observations" and isinstance(data, dict):
            # Keep full detail visible, but summarize the potentially large sample array.
            view = dict(data)
            view["samples"] = {"count": len(data.get("samples", [])), "first": (data.get("samples") or [])[:3], "last": (data.get("samples") or [])[-3:]}
            print(json.dumps(view, indent=2, ensure_ascii=False))
            print("(Use --raw to display every sample and every stored field.)")
        elif key == "events" and isinstance(data, list):
            for event in data:
                print(json.dumps(event, ensure_ascii=False, sort_keys=True))
        else:
            print(json.dumps(data, indent=2, ensure_ascii=False, sort_keys=True) if not isinstance(data, str) else data)
    print(f"\nReport file: {selected}")
    print("Use 'bbj inspect --latest --raw' to display the entire JSON, including every sample.")
    return 0


def cmd_events(args: argparse.Namespace) -> int:
    path = state_dir() / "events.jsonl"
    if not path.exists():
        print("No events yet.")
        return 0
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        print(f"Could not read events: {exc}", file=sys.stderr)
        return 1
    for line in lines[-args.limit :]:
        print(line)
    return 0


def cmd_policy(args: argparse.Namespace) -> int:
    try:
        policy = load_policy(args.file)
    except ValueError as exc:
        print(f"Policy error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(policy, indent=2))
    print("Policy is valid.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bbj",
        description="BlackBoxJail — Linux sandbox with namespaces, seccomp, resource enforcement, and audit reports.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("Examples:\n  ./bbj doctor --self-test\n  ./bbj run -- /bin/echo hello\n"
                "  ./bbj run --timeout 3 --memory-mb 128 -- python3 examples/hello.py\n"
                "  ./bbj run --cgroups required -- python3 examples/hello.py\n"
                "  ./bbj report --latest\n"),
    )
    parser.add_argument("--version", action="version", version=f"BlackBoxJail {__version__}")
    sub = parser.add_subparsers(dest="subcommand", required=True)

    doctor = sub.add_parser("doctor", help="check Linux environment and execute a sandbox smoke test")
    doctor.add_argument("--self-test", action="store_true", help="run a real sandbox smoke test")

    run = sub.add_parser("run", help="execute a command in an isolated Linux sandbox")
    run.add_argument("--policy", help="JSON policy file")
    run.add_argument("--workspace", help="host directory writable by the workload (default: new private per-run directory)")
    run.add_argument("--timeout", type=float, help="wall-clock timeout in seconds")
    run.add_argument("--cpu-seconds", type=int, help="aggregate CPU budget when cgroups are active; otherwise per-process rlimit")
    run.add_argument("--memory-mb", type=int, help="memory ceiling in MiB")
    run.add_argument("--max-output-kb", type=int, help="stdout and stderr capture ceiling per stream in KiB")
    run.add_argument("--max-processes", type=int, help="maximum concurrent workload processes (hard with cgroups, sampled otherwise)")
    run.add_argument("--max-open-files", type=int, help="per-process open file descriptor limit")
    run.add_argument("--max-file-mb", type=int, help="hard per-file write limit in MiB (not an aggregate disk quota)")
    network_group = run.add_mutually_exclusive_group()
    network_group.add_argument("--network", dest="network", action="store_true",
                               help="share the host network namespace; unsafe for untrusted workloads")
    network_group.add_argument("--no-network", dest="network", action="store_false",
                               help="force network namespace isolation even if the policy enables networking")
    run.set_defaults(network=None)
    run.add_argument("--no-seccomp", action="store_true", help="disable syscall deny-list (not recommended)")
    run.add_argument("--cgroups", choices=("auto", "required", "off"), help="resource enforcement mode")
    run.add_argument("command", nargs=argparse.REMAINDER, help="command and arguments after '--'")

    report = sub.add_parser("report", help="list JSON execution reports or display the latest")
    report.add_argument("--latest", action="store_true", help="show newest report as JSON")
    report.add_argument("--limit", type=int, default=10, help="number of report entries to list")

    inspect = sub.add_parser("inspect", help="display all recorded data and analysis for a run")
    inspect.add_argument("--latest", action="store_true", help="inspect the newest report (default)")
    inspect.add_argument("--run-id", help="inspect a specific run ID")
    inspect.add_argument("--raw", action="store_true", help="print the complete JSON including all samples")

    events = sub.add_parser("events", help="show recent JSONL audit events")
    events.add_argument("--limit", type=int, default=50, help="number of recent events")

    policy = sub.add_parser("policy", help="validate and print JSON policy")
    policy.add_argument("file", nargs="?", default=None, help="policy file (omit for defaults)")

    benchmark = sub.add_parser("benchmark", help="run safe, reproducible sandbox feature checks")
    benchmark.add_argument("--cgroups", choices=("auto", "required", "off"), default="auto",
                           help="resource enforcement mode for each scenario")
    benchmark.add_argument("--memory-mb", type=int, default=128, help="memory limit used by scenarios")
    benchmark.add_argument("--output-kb", type=int, default=4, help="output cap used by scenarios")

    measure = sub.add_parser("measure", help="compare native and sandboxed launch overhead using fixed safe probes")
    measure.add_argument("--iterations", type=int, default=10,
                         help="paired samples per mode and workload (3–100; default 10)")
    measure.add_argument("--cgroups", choices=("auto", "required", "off"), default="off",
                         help="resource enforcement mode for sandboxed probes")

    audit = sub.add_parser("audit", help="verify the tamper-evident JSONL event chain")
    audit.add_argument("--file", help="journal path (default: BlackBoxJail state events.jsonl)")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.subcommand == "doctor":
        return cmd_doctor(args.self_test)
    if args.subcommand == "run":
        return cmd_run(args)
    if args.subcommand == "report":
        if args.limit < 1:
            parser.error("report --limit must be at least 1")
        return cmd_report(args)
    if args.subcommand == "inspect":
        return cmd_inspect(args)
    if args.subcommand == "events":
        if args.limit < 1:
            parser.error("events --limit must be at least 1")
        return cmd_events(args)
    if args.subcommand == "policy":
        return cmd_policy(args)
    if args.subcommand == "benchmark":
        if args.memory_mb < 32 or args.output_kb < 1:
            parser.error("benchmark limits must be at least 32 MiB memory and 1 KiB output")
        return print_benchmarks(cgroups=args.cgroups, memory_limit_mb=args.memory_mb, output_kb=args.output_kb)
    if args.subcommand == "measure":
        if not 3 <= args.iterations <= 100:
            parser.error("measure --iterations must be between 3 and 100")
        return print_overhead_measurement(iterations=args.iterations, cgroups=args.cgroups)
    if args.subcommand == "audit":
        journal = Path(args.file).expanduser() if args.file else state_dir() / "events.jsonl"
        result = verify_journal(journal)
        print(json.dumps(result, indent=2))
        if result["valid"]:
            if not result["checked"]:
                print("No hash-chained events found; this may be a legacy journal.")
            elif result.get("legacy_unhashed_lines", 0):
                print(f"Verified {result['checked']} hash-chained events, but {result['legacy_unhashed_lines']} legacy/ unhashed rows remain unverified.")
            else:
                print("Audit hash chain valid and fully hashed.")
            return 0
        print("Audit chain verification failed.", file=sys.stderr)
        return 1
    parser.error("unknown command")
    return 2
