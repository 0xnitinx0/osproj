"""Bounded event buffer and tamper-evident, SHA-256 hash-chained JSONL journal."""
from __future__ import annotations

from collections import deque
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
import uuid
from pathlib import Path
from typing import Any


_ZERO_HASH = "0" * 64


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _canonical(event: dict[str, Any]) -> bytes:
    return json.dumps(event, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _last_event_hash(handle: Any) -> str:
    """Read only the final journal line while holding the append lock."""
    handle.seek(0, 2)
    end = handle.tell()
    if end == 0:
        return _ZERO_HASH
    pos = end - 1
    # Ignore the final newline, then scan backwards to the previous newline.
    handle.seek(pos)
    if handle.read(1) == "\n":
        pos -= 1
    while pos >= 0:
        handle.seek(pos)
        if handle.read(1) == "\n":
            pos += 1
            break
        pos -= 1
    handle.seek(max(0, pos))
    line = handle.readline()
    try:
        last = json.loads(line)
        digest = last.get("event_hash") if isinstance(last, dict) else None
        return digest if isinstance(digest, str) and len(digest) == 64 else _ZERO_HASH
    except json.JSONDecodeError:
        # A corrupted final record must not be silently linked as a valid event.
        return "CORRUPT"


def redact_command(command: list[str]) -> list[str]:
    """Best-effort redaction of common secret-bearing flags before audit storage.

    This is intentionally conservative and is not a guarantee that arbitrary
    application-specific credentials in command arguments or output are removed.
    """
    sensitive_names = ("password", "passwd", "token", "api-key", "api_key", "secret",
                       "authorization", "access-key", "access_key", "credential")
    separate_value_flags = {"-p"}
    cleaned: list[str] = []
    redact_next = False
    for arg in command:
        if redact_next:
            cleaned.append("[REDACTED]")
            redact_next = False
            continue
        lower = arg.lower()
        if "=" in arg:
            key, _value = arg.split("=", 1)
            key_lower = key.lower().lstrip("-")
            if any(name in key_lower for name in sensitive_names):
                cleaned.append(key + "=[REDACTED]")
                continue
            # Environment assignments such as TOKEN=abc are caught above; preserve
            # all other arguments exactly as provided.
            cleaned.append(arg)
            continue
        if arg.startswith("-"):
            key_lower = lower.lstrip("-")
            if key_lower in separate_value_flags or any(name in key_lower for name in sensitive_names):
                cleaned.append(arg)
                redact_next = True
            else:
                cleaned.append(arg)
            continue
        # Header-like values can contain credentials without a flag name of their own.
        prefix = lower.split(":", 1)[0]
        if ":" in arg and any(name in prefix for name in ("authorization", "proxy-authorization", "cookie")):
            cleaned.append("[REDACTED]")
        else:
            cleaned.append(arg)
    return cleaned


class EventRecorder:
    def __init__(self, journal_path: Path, capacity: int = 512) -> None:
        self.journal_path = journal_path
        self.buffer: deque[dict[str, Any]] = deque(maxlen=capacity)
        self.journal_path.parent.mkdir(parents=True, exist_ok=True)

    def record(self, event_type: str, **fields: Any) -> dict[str, Any]:
        event: dict[str, Any] = {"event_id": "evt-" + uuid.uuid4().hex[:12], "timestamp": utc_now(), "event": event_type, **fields}
        try:
            fd = os.open(
                self.journal_path,
                os.O_CREAT | os.O_RDWR | os.O_APPEND,
                0o600,
            )
            with os.fdopen(fd, "a+", encoding="utf-8") as handle:
                try:
                    self.journal_path.chmod(0o600)
                except OSError:
                    pass
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
                os.fchmod(handle.fileno(), 0o600)
                previous = _last_event_hash(handle)
                event["prev_hash"] = previous
                event["event_hash"] = hashlib.sha256(_canonical(event)).hexdigest()
                handle.seek(0, 2)
                handle.write(json.dumps(event, sort_keys=True, ensure_ascii=False) + "\n")
                handle.flush()
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        except OSError:
            # Logging failure must not crash the supervised workload; a future audit
            # verification will expose a missing/broken chain if logging resumes.
            event["prev_hash"] = None
            event["event_hash"] = None
        self.buffer.append(event)
        return event
