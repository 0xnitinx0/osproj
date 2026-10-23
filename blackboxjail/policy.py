"""Policy loading, defaults, and strict validation."""
from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any

DEFAULT_POLICY: dict[str, Any] = {
    "timeout_seconds": 15,
    "cpu_seconds": 10,
    "memory_limit_mb": 512,
    "max_output_kb": 1024,
    "max_processes": 64,
    "max_open_files": 128,
    "max_file_mb": 64,
    "network": False,
    "seccomp": True,
    "cgroups": "auto",
}


def load_policy(path: str | None) -> dict[str, Any]:
    policy = dict(DEFAULT_POLICY)
    if path is not None:
        policy_path = Path(path).expanduser()
        try:
            with policy_path.open("r", encoding="utf-8") as handle:
                supplied = json.load(handle)
        except FileNotFoundError as exc:
            raise ValueError(f"Policy file not found: {policy_path}") from exc
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON in policy file: {exc}") from exc
        if not isinstance(supplied, dict):
            raise ValueError("Policy must be a JSON object")
        unknown = set(supplied) - set(DEFAULT_POLICY)
        if unknown:
            raise ValueError("Unknown policy key(s): " + ", ".join(sorted(unknown)))
        policy.update(supplied)

    integer_limits = ("cpu_seconds", "memory_limit_mb", "max_output_kb", "max_processes", "max_open_files", "max_file_mb")
    for key in integer_limits:
        value = policy[key]
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise ValueError(f"Policy '{key}' must be a positive integer")
    timeout = policy["timeout_seconds"]
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("Policy 'timeout_seconds' must be a finite positive number")
    if policy["max_processes"] < 2:
        raise ValueError("Policy 'max_processes' must be at least 2")
    if policy["max_open_files"] < 16:
        raise ValueError("Policy 'max_open_files' must be at least 16")
    if not isinstance(policy["network"], bool):
        raise ValueError("Policy 'network' must be true or false")
    if not isinstance(policy["seccomp"], bool):
        raise ValueError("Policy 'seccomp' must be true or false")
    if policy["cgroups"] not in ("auto", "required", "off"):
        raise ValueError("Policy 'cgroups' must be 'auto', 'required', or 'off'")
    return policy
