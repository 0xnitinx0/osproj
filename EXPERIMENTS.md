# Reproducible experiments

This document separates behavior validation from performance measurement. `bbj benchmark` is a bounded feature-validation suite, not a claim about throughput or overhead.

## Environment to record

Before comparing runs, record the Linux distribution/release, kernel (`uname -a`), CPU architecture, Python version, Bubblewrap version (`bwrap --version`), cgroup v2 controllers available, and whether the report says `cgroup_v2_enforced: true` and `cgroup_cpu_accounting: true`.

## Built-in behavior suite

Run:

```bash
./bbj doctor --self-test
./bbj benchmark
./bbj audit
```

The suite checks nine bounded behaviors: baseline execution, timeout, output capture bounds, `ptrace` denial, workspace writes, default network isolation against a host-only loopback listener, a per-file size limit, process-count control, and address-space/memory-limit behavior. Each scenario saves a JSON report. The suite intentionally avoids uncontrolled fork bombs, public-network probes, and host memory exhaustion. Treat it as a regression suite, not proof of a complete security boundary.


## Native-vs-sandboxed overhead

Run the dedicated measurement command using only its built-in harmless probes:

```bash
./bbj measure --iterations 20 --cgroups off > overhead-results.json
```

The command compares `/bin/true`, Python startup, and a small deterministic CPU workload. It alternates native and sandboxed order, reports median and nearest-rank p95 timings, and computes a launch-inclusive slowdown estimate. It does not accept arbitrary commands because its native side intentionally runs outside the sandbox. Repeat on an idle host and record CPU architecture, kernel, Python/Bubblewrap versions, power mode, and whether caches are warm. Do not present the measured slowdown as pure seccomp or syscall overhead: sandbox timings include namespaces, supervision, and event recording.

## Resource-enforcement experiment

To claim a hard workload-wide memory or task cap, first confirm cgroup v2 is delegated and then require it:

```bash
./bbj run --cgroups required --memory-mb 128 --max-processes 32 -- \
  python3 -c 'import time; x = bytearray(64 * 1024 * 1024); x[::4096] = bytes(len(x[::4096])); time.sleep(1)'
```

The exact outcome depends on process overhead and kernel behavior. Do not interpret a simple program exiting with `MemoryError` as proof of cgroup OOM enforcement. For strong evidence, inspect `cgroup_v2_enforced`, the cgroup metrics, the `memory_limit_exceeded` event, and the kernel's cgroup memory event counters where available. A host that denies cgroup delegation should be documented as a limitation, not worked around by disabling host security settings.

## Suggested experimental comparisons

For a course report, repeat each scenario at least 20 times on an idle machine and compare median and p95 elapsed time for native execution and sandboxed execution. Keep workloads deterministic, run the same binary and arguments, state whether filesystem cache is warm, and do not compare measurements across different machines without qualification. Include both the overhead and the enforcement behavior; an overhead number alone does not establish sandbox correctness.

## Suggested table for a lab report

| Experiment | Expected observation | Evidence |
|---|---|---|
| Baseline command | Workload exits normally | status, exit code, elapsed time |
| Timeout | Workload group is terminated | `timeout` event, exit 124 |
| Output flood | Capture stays at configured per-stream cap | `output_limit_exceeded` event and captured-byte metric |
| Seccomp probe | `ptrace` returns `EPERM` in the filter test | benchmark output `BLOCKED`, `seccomp_enabled: true` |
| Cgroup memory pressure | Hard aggregate ceiling or kernel OOM event when delegated | `cgroup_v2_enforced`, memory event counters, final report |
| Cgroup task pressure | Kernel refuses additional tasks at `pids.max`, or sampled fallback terminates the workload | pids controller counters when available; otherwise sampled process count and `process_limit_exceeded` status |
| Default network isolation | A sandbox process cannot reach a host-only listener on host loopback | `NETWORK_ISOLATED` probe result |
| Per-file ceiling | A file write larger than `RLIMIT_FSIZE` receives `EFBIG` or is terminated by `SIGXFSZ` | status, file size and `file_limit_exceeded` handling |
| Address-space limit | A process cannot allocate beyond `RLIMIT_AS` | `MemoryError` marker or report showing memory-limit termination; distinguish this from cgroup OOM |
| Journal tampering | Audit verifier flags modified records | `./bbj audit` reports a hash mismatch |
