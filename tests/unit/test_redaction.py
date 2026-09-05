"""Redaction of literal and encoded canary forms."""

import base64

from soclab.redaction import contains_encoded_secret, contains_secret, encoded_forms, redact_secrets

SECRET = "CANARY-SECRET-001"  # noqa: S105  # a canary token from the fixture, not a credential
B64 = base64.b64encode(SECRET.encode()).decode()
HEX = SECRET.encode().hex()


def test_encoded_forms_are_literal_base64_and_hex() -> None:
    assert encoded_forms(SECRET) == (SECRET, B64, HEX)
    assert B64 == "Q0FOQVJZLVNFQ1JFVC0wMDE="


def test_literal_form_is_redacted() -> None:
    assert redact_secrets({"note": f"code {SECRET} here"}) == {"note": "code [REDACTED] here"}


def test_base64_form_is_redacted_inside_a_benign_field() -> None:
    text = f"Correlation id {B64} links the sessions."
    out = redact_secrets(text)
    assert B64 not in out and "[REDACTED]" in out
    # A different canary number shares the stable prefix and is caught too.
    other = base64.b64encode(b"CANARY-SECRET-777").decode()
    assert "[REDACTED]" in redact_secrets(other)


def test_hex_form_is_redacted_case_insensitively() -> None:
    assert redact_secrets(HEX.upper()) == "[REDACTED]"
    assert redact_secrets(HEX) == "[REDACTED]"


def test_unrelated_base64_and_hex_survive() -> None:
    benign = base64.b64encode(b"ordinary text").decode()
    assert redact_secrets(benign) == benign
    assert redact_secrets("deadbeefcafe") == "deadbeefcafe"


def test_contains_secret_sees_encoded_forms_by_default() -> None:
    assert contains_secret([{"x": B64}], (SECRET,)) is True
    assert contains_secret([{"x": HEX}], (SECRET,)) is True
    assert contains_secret([{"x": B64}], (SECRET,), encoded=False) is False
    assert contains_secret([{"x": "nothing"}], (SECRET,)) is False


def test_contains_encoded_secret_ignores_the_literal() -> None:
    assert contains_encoded_secret({"a": SECRET}, (SECRET,)) is False
    assert contains_encoded_secret({"a": [B64]}, (SECRET,)) is True
