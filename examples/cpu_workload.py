"""Bounded CPU workload; finishes successfully and is safe for a demo."""
import hashlib
import time

started = time.monotonic()
value = b"blackboxjail"
for i in range(250_000):
    value = hashlib.sha256(value + str(i).encode()).digest()
print(f"cpu workload completed; digest={value.hex()[:16]}; elapsed={time.monotonic()-started:.3f}s")
