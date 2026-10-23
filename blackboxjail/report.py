"""JSON report persistence and simple report listing."""
from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
from typing import Any


def state_dir() -> Path:
    # Reports can include command output and filesystem paths; keep state private.
    base = Path.home() / ".local" / "state"
    configured = os.environ.get("XDG_STATE_HOME")
    if configured:
        candidate = Path(configured).expanduser()
        if candidate.is_absolute():
            base = candidate
    path = base / "blackboxjail"
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        path.chmod(0o700)
    except OSError:
        pass
    return path


def reports_dir() -> Path:
    path = state_dir() / "reports"
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        path.chmod(0o700)
    except OSError:
        pass
    return path


def save_report(report: dict[str, Any]) -> Path:
    path = reports_dir() / f"{report['run_id']}.json"
    tmp = path.with_suffix(".json.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            os.fchmod(handle.fileno(), 0o600)
            json.dump(report, handle, indent=2, ensure_ascii=False, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        tmp.replace(path)
        os.chmod(path, 0o600)
    except Exception:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        raise
    return path


def list_reports() -> list[Path]:
    path = reports_dir()
    return sorted(path.glob("*.json"), key=lambda item: item.stat().st_mtime, reverse=True)
