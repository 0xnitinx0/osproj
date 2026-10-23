# Changelog

## 2.2.0 — evaluation and regression coverage

- Added `bbj measure` for paired native-versus-sandbox launch overhead measurements using fixed, harmless workloads, reporting median, p95, slowdown factor and overhead.
- Expanded the bounded behavior suite to validate default network isolation, per-file caps, process pressure and memory/address-space behavior; save each suite as private JSON evidence with kernel, architecture, Python, and scenario metadata.
- Added tests for measurement statistics and command parsing; CI now runs the overhead probes as well as feature validation.
- Mounted `/usr/local` read-only when present so a common local Python runtime is available inside the filesystem namespace.
- Updated the experiment protocol and project documentation to distinguish launch-inclusive measurements from microbenchmarks.

## 2.1.0 — hardening and observability

- Added an architecture-checked seccomp classic-BPF deny-list for x86-64 and ARM64, including kernel module/kexec interfaces, mount API, tracing interfaces, io_uring, and other privileged syscall families.
- Added optional cgroup v2 memory and process-count enforcement, with aggregate CPU accounting and supervisor termination when available.
- Reworked output supervision to use non-blocking pipes and cap captured stdout/stderr without writing potentially unbounded output to temporary files.
- Added safe per-run workspaces by default, strict workspace path checks, private report/journal permissions, and command-secret redaction for common patterns.
- Added hash-chained event journal verification, diagnostics, and reproducible bounded behavior-validation scenarios.
- Added Linux integration tests, a CI workflow, a threat model, experiment protocol, and live demo script.
- Explicitly documents limitations: sampled fallbacks are not hard limits; the audit hash chain is not signed; Bubblewrap and Linux kernel policy still require host-specific validation.

## 2.3.0 — Black-box report and investigation foundation

- Added bounded timestamped runtime resource samples to execution reports.
- Added host/runtime metadata, explicit limit flags, and collection-health/coverage metadata.
- Added deterministic, evidence-linked behaviour fingerprints and failure findings in `blackboxjail/analyzer.py`.
- Added `bbj inspect` for readable full-run inspection and `bbj inspect --raw` for the complete stored JSON.
- Added successful, bounded CPU/memory/process example workloads and intentional non-zero-exit/timeout fixtures.
- Added `examples/demo_suite.sh` for an end-to-end demonstration on a Linux host with Bubblewrap available.
- Explicitly documents that syscall, detailed filesystem, and network tracing are not yet collected by this version; seccomp remains an enforcement filter, not a syscall history.


## 2.3.1 — integration-test fix

- Fixed missing `platform` and `sys` imports in the execution-report host metadata path, which caused sandbox integration tests to raise `NameError` after workload execution.

## 2.3.2 — restricted-host network isolation fallback

- Detects the specific Bubblewrap loopback `RTM_NEWADDR` permission failure before launching a workload.
- On that failure only, keeps user/PID/IPC/UTS/mount isolation and installs seccomp network-syscall denials rather than silently exposing host networking.
- Adds explicit report/event fields for the network isolation method and fallback reason; prints a warning when the fallback is active.
- Adds x86-64 and ARM64 seccomp rules blocking socket operations and io_uring in fallback mode.
- Adds tests for fallback command construction, syscall coverage, and kernel-level socket denial.
