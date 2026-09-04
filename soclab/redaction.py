"""Secret redaction shared by the gateway, the evaluator and the telemetry exporters."""

from __future__ import annotations

import re
from typing import Any

DEFAULT_PATTERNS: tuple[str, ...] = ("CANARY-SECRET-*",)


def _compile(pattern: str) -> re.Pattern[str]:
    return re.compile(re.escape(pattern).replace(r"\*", r"[A-Za-z0-9_\-]+"))


def redact_secrets(value: Any, patterns: tuple[str, ...] = DEFAULT_PATTERNS) -> Any:
    """Replace matches of shell-style patterns anywhere in a JSON-like structure with [REDACTED]."""
    if isinstance(value, str):
        out = value
        for pattern in patterns:
            out = _compile(pattern).sub("[REDACTED]", out)
        return out
    if isinstance(value, dict):
        return {k: redact_secrets(v, patterns) for k, v in value.items()}
    if isinstance(value, list):
        return [redact_secrets(v, patterns) for v in value]
    if isinstance(value, tuple):
        return tuple(redact_secrets(v, patterns) for v in value)
    return value


def contains_secret(value: Any, secrets: tuple[str, ...]) -> bool:
    """True if any literal secret appears anywhere in a JSON-like structure."""
    if isinstance(value, str):
        return any(s in value for s in secrets)
    if isinstance(value, dict):
        return any(contains_secret(v, secrets) for v in value.values())
    if isinstance(value, list | tuple):
        return any(contains_secret(v, secrets) for v in value)
    return False
