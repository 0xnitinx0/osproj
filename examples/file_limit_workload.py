"""Intentional per-file size-limit fixture; stops when write is denied or signal arrives."""
from pathlib import Path

path = Path("oversized-output.bin")
chunk = b"X" * (1024 * 1024)
written = 0
with path.open("wb") as handle:
    while True:
        handle.write(chunk)
        handle.flush()
        written += len(chunk)
print(f"unexpectedly completed; bytes={written}")
