"""Verify the SHA-256 hash chain in the JSONL event journal."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from .events import _ZERO_HASH, _canonical


def verify_journal(path: Path) -> dict[str, Any]:
    checked = 0
    legacy = 0
    previous_hash = _ZERO_HASH
    errors: list[str] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        return {"valid": False, "checked": 0, "legacy": 0, "errors": [str(exc)]}

    for line_number, line in enumerate(lines, start=1):
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            errors.append(f"line {line_number}: invalid JSON")
            continue
        if not isinstance(event, dict) or not isinstance(event.get("event_hash"), str):
            legacy += 1
            continue
        saved_hash = event.pop("event_hash", None)
        saved_previous = event.get("prev_hash")
        if saved_previous != previous_hash:
            errors.append(f"line {line_number}: previous-hash mismatch")
        computed = hashlib.sha256(_canonical(event)).hexdigest()
        if saved_hash != computed:
            errors.append(f"line {line_number}: event hash mismatch")
        previous_hash = saved_hash if isinstance(saved_hash, str) else previous_hash
        checked += 1
    return {
        "valid": not errors,
        "complete": bool(checked) and legacy == 0 and not errors,
        "checked": checked,
        "legacy_unhashed_lines": legacy,
        "head_hash": previous_hash,
        "errors": errors,
    }
