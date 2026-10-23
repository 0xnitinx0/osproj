# BlackBoxJail

**A Linux workload sandbox and black-box runtime behaviour analysis prototype.**

BlackBoxJail launches a command inside Bubblewrap-created namespaces, exposes a deliberately small read-only runtime filesystem, restricts network access by default, and supervises execution for time, memory, process-count, output, descriptor, and per-file limits. It records structured JSON reports and a SHA-256 hash-chained JSONL event journal.

> **Project status:** educational OS/security engineering prototype. It is useful for studying and demonstrating real Linux isolation primitives, but it is not a formally audited boundary for arbitrary hostile multi-tenant code. Use a patched Linux host and do not run BlackBoxJail itself as root for ordinary workloads.

## Why it stands out

- **Real Linux mechanisms, not a simulation:** mount, PID, IPC, UTS and user namespaces via Bubblewrap, plus a network namespace where supported; an explicit capability drop; seccomp classic-BPF syscall filtering; cgroup v2 enforcement when delegated; and kernel resource limits via `setrlimit`. If a host specifically denies loopback setup, a reported seccomp network-syscall-blocking fallback keeps networking restricted without pretending a separate network namespace exists.
- **Fail-visible enforcement:** the report states whether cgroup v2 was active and why it fell back. In fallback mode, memory and process counts are sampled from `/proc` rather than represented as hard aggregate caps.
- **Safe-by-default workspace:** omitted `--workspace` creates a private per-run directory under BlackBoxJail state. Only that workspace is mounted writable into the sandbox.
- **Evidence, not just a success message:** run metrics, structured events, sampled runtime timelines, explainable failure findings, behavioural fingerprints, a hash-chain verifier, and bounded adversarial behaviour checks.
- **Privacy-aware logging:** state/report directories are owner-only where POSIX permissions are available; common secret-bearing command flags are redacted before recording.
- **Supports Linux x86-64 and ARM64/aarch64** for the built-in seccomp profile, with architecture mismatch and x32 ABI checks on x86-64.

## Quick start — Ubuntu / Debian

**From the downloaded ZIP:** extract it, open a terminal in the extracted `blackboxjail` directory, and run:

```bash
chmod +x bbj setup.sh
./setup.sh
```

**From a Git repository:** after the project has been published, clone its repository URL, enter the project directory, and run the same two commands above.

The setup script requires Python 3.10+ and Bubblewrap. On Debian/Ubuntu it installs Bubblewrap via `apt` if missing (using `sudo` when needed), then runs the tests and checks whether a real sandbox can launch. No pip packages are required.

Manual installation:

```bash
sudo apt update
sudo apt install -y python3 bubblewrap
./bbj doctor --self-test
```

If the host allows user namespaces but Bubblewrap cannot configure loopback (`bwrap: loopback: Failed RTM_NEWADDR: Operation not permitted`), BlackBoxJail switches to a more restrictive seccomp network-syscall block while retaining the other namespaces. The report labels this as `seccomp_network_syscall_block`; it is not a separate network namespace and can restrict Unix-domain socket use. If user/mount/PID namespace creation itself is denied, the sandbox still fails closed. Do not “fix” this by blindly making Bubblewrap setuid or weakening host security controls.

## First run

Run commands from the repository directory:

```bash
# Environment diagnostics and an actual sandbox smoke test
./bbj doctor --self-test

# Run a tiny command; a private per-run workspace is created automatically
./bbj run -- /bin/echo "Hello from BlackBoxJail"

# Run a project example
./bbj run --timeout 5 --cpu-seconds 2 --memory-mb 256 -- python3 examples/hello.py

# Apply the committed policy file
./bbj run --policy policies/default.json -- python3 examples/write_workspace.py

# Inspect a report, event trail and audit integrity
./bbj report --latest

# Readable full inspection of the latest run
./bbj inspect --latest

# Complete raw JSON, including every collected resource sample
./bbj inspect --latest --raw
./bbj events --limit 20
./bbj audit

# Execute bounded security/behavior validation scenarios
./bbj benchmark --cgroups off

# Measure native-vs-sandboxed launch overhead using fixed safe probes
./bbj measure --iterations 10 --cgroups off
```

Every argument after `--` belongs to the workload. When you explicitly pass `--workspace DIR`, the workload can modify or delete files in that host directory. Use a disposable directory when testing unknown code.

## What is enforced

| Control | Mechanism | Important caveat |
|---|---|---|
| Filesystem view | Bubblewrap mount namespace; selected system runtime paths are read-only; private `/tmp`, `/run`, `/dev/shm` | The selected workspace is writable. The host kernel and mounted runtime files remain trusted. |
| Network | New network namespace by default; if a host specifically denies Bubblewrap's loopback setup, a seccomp fallback blocks socket/network syscalls | The fallback is not a separate network namespace and can break AF_UNIX socket use. The report identifies the active method. `--network` shares the host network namespace; use it only for workloads you trust. |
| Syscalls | Architecture-checked seccomp classic-BPF deny-list | A deny-list is not an allow-list and does not make every allowed syscall safe. |
| Wall-clock timeout | Supervisor kills workload after the deadline | There can be a small scheduling/termination overshoot. |
| CPU time | `RLIMIT_CPU` per process; cgroup aggregate CPU usage accounting plus supervisor termination when the CPU controller is delegated | Aggregate termination is sampled and can overshoot; this is not a kernel-configured hard aggregate CPU-time quota. |
| Memory | Per-process `RLIMIT_AS`; cgroup `memory.max` when delegated; otherwise `/proc` RSS sampling and kill | RSS sampling can miss brief spikes; `RLIMIT_AS` is not an aggregate tree-memory limit. |
| Process count | cgroup `pids.max` when delegated; otherwise sampled process-tree count | The fallback is sampled and can miss short-lived bursts. |
| Output capture | Supervisor caps stdout and stderr separately | The cap is on captured output, not a total disk quota. |
| File size | Kernel `RLIMIT_FSIZE` per file | This limits one file at a time; it is not an aggregate workspace storage quota. |
| File descriptors/core dumps | `RLIMIT_NOFILE`; core dumps disabled | Limits are inherited by the workload. |
| Audit | JSONL events linked with SHA-256 hashes | A local hash chain is tamper-evident, not signed or protected from an attacker who can rewrite the entire journal. |

BlackBoxJail deliberately distinguishes **hard controls** from **sampled fallback observations** in the report. Use `--cgroups required` to refuse launch unless cgroup v2 resource controllers are delegated and working; use `--cgroups off` to demonstrate and test the fallback path.

## CLI reference

```text
./bbj doctor [--self-test]
./bbj run [--policy FILE] [--workspace DIR]
          [--timeout SECONDS] [--cpu-seconds SECONDS]
          [--memory-mb MiB] [--max-output-kb KiB]
          [--max-processes N] [--max-open-files N] [--max-file-mb MiB]
          [--network] [--no-seccomp] [--cgroups auto|required|off]
          -- COMMAND [ARG ...]
./bbj report [--latest] [--limit N]
./bbj events [--limit N]
./bbj policy [FILE]
./bbj audit [--file JOURNAL]
./bbj benchmark [--cgroups auto|required|off] [--memory-mb MiB] [--output-kb KiB]
./bbj measure [--iterations 3..100] [--cgroups auto|required|off]
```

Exit codes from the workload are preserved when it completes normally. BlackBoxJail uses `124` for timeout, `125` for a supervised limit, and `126` for a launch error. A per-file limit can also result in `file_limit_exceeded`/`125` if the workload receives `SIGXFSZ`.

## Reports and logs

State is written to `${XDG_STATE_HOME:-~/.local/state}/blackboxjail/`:

```text
blackboxjail/
├── events.jsonl       # append-only hash-linked event records
├── reports/           # one JSON report per run (private permissions)
├── benchmarks/        # machine-readable benchmark suite summaries
└── workspaces/        # private workspaces created by default runs
```

### Black-box observations and failure investigation

The report schema stores `observations.samples` (timestamped CPU/memory/process samples), observation coverage, collection health, sandbox enforcement state, stdout/stderr, supervisor events, a `analysis.fingerprint`, and `analysis.findings`. The analysis currently uses deterministic rules for timeout, memory pressure/exhaustion, CPU/process/output/file limits, launch failures, unexpected non-zero exits, and operator interruption. Findings include a stable rule ID, category, severity, confidence label, summary, evidence event IDs, missing evidence, and alternative explanations.

Important limitations: syscall, file-operation, and network-operation histories are explicitly marked as not enabled in this version; seccomp is an enforcement filter, not a complete syscall tracer. Resource samples are capped at 2,000 per report and the in-memory event list is bounded; collection health notes the sample cap and event-buffer truncation. `inspect --raw` displays all stored report fields and all retained samples. These findings describe observed behaviour and are not proof of malicious intent or definitive root cause.

Example workloads:

```bash
./bbj run -- python3 examples/hello.py
./bbj run --timeout 8 --cpu-seconds 6 -- python3 examples/cpu_workload.py
./bbj run -- python3 examples/fail_nonzero.py  # expected application exit 23
./bbj run --timeout 1 -- python3 examples/timeout_workload.py  # expected timeout
./examples/demo_suite.sh  # end-to-end demonstration suite
```

Each report includes the sanitized command, effective configuration, enforcement backend state, elapsed time, output sizes, sampled or cgroup metrics, events and output. Version 2.3 adds bounded timestamped resource samples, collection-coverage metadata, a behavioural fingerprint, and deterministic evidence-linked findings. Use `./bbj inspect --latest` for a readable view or `./bbj inspect --latest --raw` to print the entire JSON report. Each `bbj benchmark` run also writes a separate owner-only JSON suite summary under `benchmarks/`, recording host/kernel/Python details and per-scenario outcomes. Command redaction covers common patterns such as `--token value`, `--api-key=value`, `TOKEN=value`, and authorization headers, but arbitrary secrets in command text or workload output cannot be reliably discovered; avoid passing secrets to untrusted workloads.

`bbj audit` checks the integrity of the local JSONL hash chain. It does not provide cryptographic signatures or remote log anchoring, and should not be described as immutable against a privileged attacker.

## Project layout

```text
blackboxjail/
├── bbj                          # lightweight CLI launcher
├── setup.sh                     # dependency check, tests, real smoke test
├── CHANGELOG.md                 # version history
├── blackboxjail/
│   ├── cli.py                   # CLI and diagnostics
│   ├── sandbox.py               # Bubblewrap orchestration and supervisor
│   ├── cgroups.py               # delegated cgroup v2 resource controls
│   ├── seccomp.py               # architecture-specific cBPF filter
│   ├── monitor.py               # /proc process-tree sampling fallback
│   ├── policy.py                # strict policy schema validation
│   ├── events.py                # private, hash-chained event journal
│   ├── audit.py                 # journal integrity verification
│   ├── benchmark.py             # bounded security/behavior validation suite
│   ├── measure.py               # native-vs-sandboxed overhead measurement
│   └── report.py                # private JSON report storage
├── policies/default.json
├── examples/
├── tests/
├── docs/architecture.md
├── docs/demo-script.md
├── THREAT_MODEL.md
└── EXPERIMENTS.md
```

## Development and validation

```bash
python3 -m unittest discover -s tests -v
./bbj doctor --self-test
./bbj benchmark --cgroups off
./bbj measure --iterations 10 --cgroups off
./bbj audit
```

Pure-Python tests validate policy parsing, audit-chain detection, report/log permissions, CLI configuration, and seccomp filter construction (including a kernel-level ptrace-denial test on supported Linux hosts). Bubblewrap integration tests are skipped when Bubblewrap is not installed; the CI workflow installs it and executes the smoke test and bounded behavior suite.

`bbj measure` uses only fixed, harmless commands; it compares native process-launch time with sandboxed end-to-end launch/supervisor time and reports median/p95 plus relative overhead. It is not a syscall microbenchmark; repeat runs on an idle host and report the environment.

See [`docs/architecture.md`](docs/architecture.md), [`THREAT_MODEL.md`](THREAT_MODEL.md), [`EXPERIMENTS.md`](EXPERIMENTS.md), and [`docs/demo-script.md`](docs/demo-script.md) for the design, threat model, evaluation protocol, and live demonstration plan.
