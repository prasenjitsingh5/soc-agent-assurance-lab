"""The grant signing key honours the documented environment variable."""

from __future__ import annotations

import pytest

from soclab.grants import GrantSigner


def test_unset_variable_gives_a_fresh_random_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SOCLAB_GRANT_SIGNING_KEY", raising=False)
    first = GrantSigner.from_environment()
    second = GrantSigner.from_environment()
    assert first._key != second._key


def test_blank_variable_behaves_like_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SOCLAB_GRANT_SIGNING_KEY", "   ")
    assert len(GrantSigner.from_environment()._key) == 32


def test_set_variable_is_used_for_every_signer(monkeypatch: pytest.MonkeyPatch) -> None:
    key = "k" * 40
    monkeypatch.setenv("SOCLAB_GRANT_SIGNING_KEY", key)
    first = GrantSigner.from_environment()
    second = GrantSigner.from_environment()
    assert first._key == second._key == key.encode()


def test_short_key_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SOCLAB_GRANT_SIGNING_KEY", "too-short")
    with pytest.raises(ValueError, match="at least 32 bytes"):
        GrantSigner.from_environment()
