# BlackBoxJail threat model

## Goal

Limit the operating-system interfaces and resources available to a single untrusted workload while producing evidence about how it ran. The intended use is a student OS project, local experiment runner, or defensive teaching tool.

## Assets

- Host files outside the selected workspace
- Host network connectivity
- Host memory, CPU time, process table and temporary storage
- Per-user reports and audit records
- Correctness of reported isolation and resource enforcement

## Adversary assumptions

A workload may be buggy or malicious. It may attempt to access files outside the workspace, use networking, create processes or threads, consume memory/CPU, flood stdout/stderr, create huge files, call risky syscalls, or outlive its original process. It does not have a kernel exploit or a privilege-escalation vulnerability in the host kernel/Bubblewrap. The user running BlackBoxJail and the kernel are trusted.

## Controls

- Bubblewrap creates mount, PID, IPC, UTS and user namespaces and normally a network namespace, and explicitly drops all Linux capabilities from the sandboxed workload. On hosts that specifically deny loopback setup, a seccomp fallback blocks network socket syscalls while reporting that no separate network namespace was created.
- The filesystem is assembled from a small read-only runtime plus an explicitly selected writable workspace; `/tmp`, `/dev/shm`, and `/run` are size-bounded tmpfs mounts.
- A compiled, architecture-checked seccomp cBPF profile returns `EPERM` for selected high-risk syscall families.
- Per-process limits constrain CPU time, address space, file size, open file descriptors, core dumps and locked memory.
- Where cgroup v2 is delegated, `memory.max`, `pids.max`, OOM-group behavior and aggregate CPU accounting strengthen workload-wide resource controls.
- Otherwise, the runner explicitly reports the weaker fallback: per-process rlimits plus sampled `/proc` RSS/process metrics.
- Non-blocking stdout/stderr pipes enforce capture limits without spooling unlimited output to host disk.
- Reports and event logs are stored in per-user directories with restrictive permissions. Event records use a SHA-256 hash chain; common secret-bearing CLI flags are redacted before command journaling.

## Explicit non-goals and residual risks

- This is not an audited container runtime and is not a complete production security boundary.
- The seccomp profile is a focused deny-list, not a syscall allow-list. It does not prove that every syscall is harmless.
- Host kernel, Bubblewrap, runtime libraries and mounted system tools remain trusted computing base components.
- `--network` reuses the host network namespace and materially weakens isolation; do not use it for untrusted workloads.
- The selected workspace is writable and can be modified or deleted by the workload. The project blocks common system roots, the entire home directory and common credential directories as workspaces, but users must still choose their writable directory deliberately.
- There is no aggregate quota for all bytes written to the selected host workspace. `RLIMIT_FSIZE` caps individual files only.
- Without delegated cgroup v2 controllers, exact aggregate memory, CPU, and task-count limits are not guaranteed. `auto` reports this; `required` refuses to launch without cgroups.
- The SHA-256 chain detects edits, omissions in the middle, and reordering when checked, but it is not digitally signed. An attacker who can rewrite the entire journal can recompute the chain; export/anchor the final hash elsewhere for stronger assurance.
- Best-effort argument redaction only recognizes common credential flag patterns. It cannot redact every application-specific secret or secrets emitted by workload stdout/stderr.
- Workloads can exploit kernel bugs or runtime bugs; do not run malware or high-risk samples on a personal workstation.

## Recommended operating practice

1. Run as a normal user, never with `sudo`.
2. Keep network isolation and seccomp enabled.
3. Prefer the default private per-run workspace, or pass a fresh disposable directory to `--workspace`.
4. For experiments intended to prove hard aggregate resource caps, use `--cgroups required` and verify `cgroup_v2_enforced` and `cgroup_cpu_accounting` in the report.
5. Check `./bbj audit` and archive the journal head hash outside the machine if the integrity of the record matters.
