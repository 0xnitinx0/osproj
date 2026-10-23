"""Moderate, bounded memory workload; intended to finish under default limits."""
blocks = [bytearray(1024 * 1024) for _ in range(24)]
for index, block in enumerate(blocks):
    block[0] = index
print(f"memory workload completed; allocated={len(blocks)} MiB")
