"""Secret redaction shared by the gateway, the evaluator and the telemetry exporters.

Patterns are shell style: ``CANARY-SECRET-*``. Besides the literal form, the
redactor recognizes two encodings of the literal prefix, standard base64 and
lowercase or uppercase hex, so a secret copied into a benign looking field in
an encoded form is still removed. Base64 is matched on the longest prefix whose
encoding does not depend on the characters that follow it (whole 3-byte
groups). This is deliberately narrow: it catches the configured canaries in
those encodings and nothing else. It is not a general secret detector.
"""

from __future__ import annotations

import base64
import re
from typing import Any

DEFAULT_PATTERNS: tuple[str, ...] = ("CANARY-SECRET-*",)

_B64_TAIL = r"[A-Za-z0-9+/]*={0,2}"
_HEX_TAIL = r"[0-9a-fA-F]*"


def _literal_prefix(pattern: str) -> str:
    return pattern.split("*", 1)[0]


def _compile(pattern: str) -> tuple[re.Pattern[str], ...]:
    literal = re.compile(re.escape(pattern).replace(r"\*", r"[A-Za-z0-9_\-]+"))
    prefix = _literal_prefix(pattern)
    variants: list[re.Pattern[str]] = [literal]
    stable = prefix[: len(prefix) // 3 * 3]
    if len(stable) >= 6:
        encoded = base64.b64encode(stable.encode("utf-8")).decode("ascii")
        variants.append(re.compile(re.escape(encoded) + _B64_TAIL))
    if len(prefix) >= 4:
        variants.append(re.compile(re.escape(prefix.encode("utf-8").hex()) + _HEX_TAIL, re.IGNORECASE))
    return tuple(variants)


def redact_secrets(value: Any, patterns: tuple[str, ...] = DEFAULT_PATTERNS) -> Any:
    """Replace matches of shell-style patterns, literal or encoded, anywhere in a JSON-like structure."""
    if isinstance(value, str):
        out = value
        for pattern in patterns:
            for compiled in _compile(pattern):
                out = compiled.sub("[REDACTED]", out)
        return out
    if isinstance(value, dict):
        return {k: redact_secrets(v, patterns) for k, v in value.items()}
    if isinstance(value, list):
        return [redact_secrets(v, patterns) for v in value]
    if isinstance(value, tuple):
        return tuple(redact_secrets(v, patterns) for v in value)
    return value


def encoded_forms(secret: str) -> tuple[str, ...]:
    """The literal secret plus its standard base64 and hex encodings."""
    raw = secret.encode("utf-8")
    return (secret, base64.b64encode(raw).decode("ascii"), raw.hex())


def _text_contains(text: str, secrets: tuple[str, ...], *, encoded: bool) -> bool:
    lowered = text.lower()
    for secret in secrets:
        forms = encoded_forms(secret) if encoded else (secret,)
        if secret in text or any(f in text or f.lower() in lowered for f in forms[1:]):
            return True
    return False


def contains_secret(value: Any, secrets: tuple[str, ...], *, encoded: bool = True) -> bool:
    """True if any literal secret, or with ``encoded`` its base64 or hex form, appears in the structure."""
    if isinstance(value, str):
        return _text_contains(value, secrets, encoded=encoded)
    if isinstance(value, dict):
        return any(contains_secret(v, secrets, encoded=encoded) for v in value.values())
    if isinstance(value, list | tuple):
        return any(contains_secret(v, secrets, encoded=encoded) for v in value)
    return False


def contains_encoded_secret(value: Any, secrets: tuple[str, ...]) -> bool:
    """True only when an encoded form of a secret appears, whether or not the literal also does."""
    encoded_only = tuple(form for s in secrets for form in encoded_forms(s)[1:])
    return contains_secret(value, encoded_only, encoded=False)
