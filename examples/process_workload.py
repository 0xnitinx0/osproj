"""Bounded process fixture: starts a few short-lived child processes."""
import subprocess
import sys

children = [subprocess.Popen([sys.executable, "-c", "print('child-ok')"]) for _ in range(4)]
for child in children:
    child.wait(timeout=3)
print(f"process workload completed; children={len(children)}")
