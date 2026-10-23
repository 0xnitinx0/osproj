# Live demo script (about 4 minutes)

Run this on a standard Ubuntu/Debian Linux machine with Bubblewrap installed. Keep the tests on disposable workspaces.

## 1. Verify prerequisites

```bash
./bbj doctor --self-test
```

Explain that this launches a real workload, not a drawing of namespaces. Point out whether cgroup v2 is actually delegated or whether the supervisor has selected its explicitly reported sampling fallback.

## 2. Show an ordinary isolated run

```bash
./bbj run -- /bin/echo "Hello from BlackBoxJail"
./bbj report --latest
```

Point to the effective policy, namespace/backend description, execution duration, captured output, and report path.

## 3. Show denied syscall behavior

```bash
./bbj benchmark --cgroups off
```

The bounded behavior suite checks baseline execution, a short timeout, output flooding (while capping capture), `ptrace` denial, an explicit workspace write, host-loopback network isolation, the kernel per-file ceiling, process-count pressure, and the address-space ceiling. It writes a private machine-readable JSON suite summary with environment metadata and links to each per-run report. The network test only contacts a local listener owned by the test process; it does not contact the public internet. Do not replace these tests with an uncontrolled fork bomb or unbounded memory exhaustion.

## 4. Show the audit trail

```bash
./bbj events --limit 15
./bbj audit
```

Explain the `prev_hash` / `event_hash` chain and show that editing an event payload causes verification to report a mismatch. Clarify that this is tamper-evident local logging, not signed evidence against a privileged attacker.

## 5. Discuss an honest limitation

Run with `--cgroups off` and compare the report to a system where cgroup v2 is delegated. The point is that BlackBoxJail does not silently label sampled RSS as a hard aggregate memory cap. The backend state is part of the evidence.

## 6. Quantify launch overhead

```bash
./bbj measure --iterations 10 --cgroups off > overhead-results.json
python3 -m json.tool overhead-results.json | less
```

Explain that the command only uses fixed, harmless probes and alternates native and sandboxed order. The result reports median and p95 launch-inclusive timings; it is not a pure syscall/seccomp benchmark. Run on an idle machine and note kernel, CPU, Python and Bubblewrap versions.

## What to be ready to explain

- Why namespaces, explicit capability dropping and seccomp serve different purposes.
- Why cgroups are stronger for aggregate tree resource limits than per-process rlimits.
- Why output must be drained non-blockingly to avoid pipe deadlocks.
- Why a deny-list is not the same as a syscall allow-list.
- What a hash chain detects and what it does not protect against.
