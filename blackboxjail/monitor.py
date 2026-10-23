"""Low-overhead Linux /proc process-tree sampler (best-effort fallback metrics)."""
from __future__ import annotations

from pathlib import Path
import os
from typing import Any

_PROC = Path("/proc")
_PAGE_SIZE = os.sysconf("SC_PAGE_SIZE")
_CLOCK_TICKS = os.sysconf("SC_CLK_TCK")


def _read_proc_stat(pid: int) -> tuple[int, int, int] | None:
    """Return (ppid, rss_bytes, cpu_ticks); tolerate processes exiting during reads."""
    try:
        raw = (_PROC / str(pid) / "stat").read_text(encoding="utf-8")
        # comm (field 2) can contain spaces and parentheses, so split after its final ')'.
        tail = raw[raw.rfind(")") + 2 :].split()
        ppid = int(tail[1])                 # stat field 4
        cpu_ticks = max(0, int(tail[11]) + int(tail[12]))  # utime + stime, fields 14/15
        rss_pages = max(0, int(tail[21]))  # stat field 24
        return ppid, rss_pages * _PAGE_SIZE, cpu_ticks
    except (OSError, ValueError, IndexError):
        return None


def process_tree_metrics(root_pid: int) -> dict[str, Any]:
    """Aggregate RSS, CPU ticks, and process count for a PID and current descendants.

    This is a sampling fallback; processes that exit between samples can make CPU
    totals incomplete. Use cgroup v2 counters for stronger aggregate accounting.
    """
    rows: dict[int, tuple[int, int, int]] = {}
    try:
        pids = [int(entry.name) for entry in _PROC.iterdir() if entry.name.isdigit()]
    except OSError:
        return {"rss_bytes": 0, "cpu_ticks": 0, "process_count": 0}

    for pid in pids:
        data = _read_proc_stat(pid)
        if data is not None:
            rows[pid] = data

    included = {root_pid}
    changed = True
    while changed:
        changed = False
        for pid, (ppid, _rss, _cpu) in rows.items():
            if ppid in included and pid not in included:
                included.add(pid)
                changed = True

    return {
        "rss_bytes": sum(rows[pid][1] for pid in included if pid in rows),
        "cpu_ticks": sum(rows[pid][2] for pid in included if pid in rows),
        "process_count": sum(pid in rows for pid in included),
        "cpu_seconds_sampled": sum(rows[pid][2] for pid in included if pid in rows) / _CLOCK_TICKS,
    }
