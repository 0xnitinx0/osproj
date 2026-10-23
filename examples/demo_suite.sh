#!/usr/bin/env bash
# End-to-end demo: one success, one CPU profile, and two intentional failures.
# Expected non-zero outcomes are handled so the script itself can finish successfully.
set -u
BBJ="$(cd "$(dirname "$0")/.." && pwd)/bbj"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

printf '\n=== 1. Successful workload ===\n'
"$BBJ" run --cgroups off -- python3 examples/hello.py
success_rc=$?
printf 'success fixture command exit: %s (expected 0)\n' "$success_rc"

printf '\n=== 2. CPU workload ===\n'
"$BBJ" run --cgroups off --timeout 8 --cpu-seconds 6 -- python3 examples/cpu_workload.py
cpu_rc=$?
printf 'CPU fixture command exit: %s (expected 0 on typical Linux hosts)\n' "$cpu_rc"

printf '\n=== 3. Intentional non-zero application failure ===\n'
"$BBJ" run --cgroups off -- python3 examples/fail_nonzero.py
fail_rc=$?
printf 'failure fixture command exit: %s (expected non-zero)\n' "$fail_rc"

printf '\n=== 4. Intentional timeout ===\n'
"$BBJ" run --cgroups off --timeout 1 --cpu-seconds 5 -- python3 examples/timeout_workload.py
timeout_rc=$?
printf 'timeout fixture command exit: %s (expected 124)\n' "$timeout_rc"

printf '\n=== 5. Inspect most recent run (the timeout) ===\n'
"$BBJ" inspect --latest

printf '\n=== Summary ===\n'
printf 'success=%s cpu=%s nonzero_failure=%s timeout=%s\n' "$success_rc" "$cpu_rc" "$fail_rc" "$timeout_rc"
printf 'Expected: success=0; cpu=0 (typical host); nonzero_failure=23; timeout=124\n'
printf 'Use ./bbj report to list reports and ./bbj inspect --latest --raw for complete JSON.\n'
