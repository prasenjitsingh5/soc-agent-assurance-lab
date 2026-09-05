"""The OPA installer never touches the network here: downloads are faked through monkeypatching."""

from __future__ import annotations

import hashlib
import os
import stat
import sys
from pathlib import Path

import pytest

from soclab.policy import opa_binary
from soclab.policy.opa_binary import (
    OPA_VERSION,
    OpaChecksumError,
    OpaInstallError,
    cached_opa_path,
    find_opa_binary,
    install_opa,
    opa_asset,
    platform_key,
    user_cache_dir,
)

GOOD_BYTES = b"pretend this is opa"


@pytest.fixture
def cache(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """Isolated cache, no env override, no opa on PATH."""
    root = tmp_path / "cache"
    monkeypatch.setenv("SOCLAB_CACHE_DIR", str(root))
    monkeypatch.delenv("SOCLAB_OPA_BINARY", raising=False)
    monkeypatch.setattr(opa_binary.shutil, "which", lambda _name: None)
    return root


def _pin_digest(monkeypatch: pytest.MonkeyPatch, payload: bytes) -> None:
    """Point the pinned digest for this platform at a known payload."""
    asset = opa_asset()
    key = (asset.system, asset.arch)
    monkeypatch.setitem(opa_binary._ASSETS, key, (asset.filename, hashlib.sha256(payload).hexdigest()))


# ----------------------------------------------------------------- platform mapping
@pytest.mark.parametrize(
    ("system", "machine", "expected"),
    [
        ("Windows", "AMD64", ("windows", "amd64")),
        ("Linux", "x86_64", ("linux", "amd64")),
        ("Linux", "aarch64", ("linux", "arm64")),
        ("Darwin", "x86_64", ("darwin", "amd64")),
        ("Darwin", "arm64", ("darwin", "arm64")),
    ],
)
def test_platform_key_normalizes_names(system: str, machine: str, expected: tuple[str, str]) -> None:
    assert platform_key(system, machine) == expected


def test_every_pinned_asset_points_at_the_pinned_release() -> None:
    for (system, machine), _ in opa_binary._ASSETS.items():
        asset = opa_asset(system, machine)
        assert asset.url.startswith(
            f"https://github.com/open-policy-agent/opa/releases/download/v{OPA_VERSION}/"
        )
        assert len(asset.sha256) == 64 and int(asset.sha256, 16)
    assert opa_asset("windows", "amd64").executable_name == "opa.exe"
    assert opa_asset("linux", "arm64").executable_name == "opa"


def test_unsupported_platform_is_refused() -> None:
    with pytest.raises(OpaInstallError, match="no pinned OPA build for linux/riscv64"):
        opa_asset("Linux", "riscv64")


# ----------------------------------------------------------------- cache location
def test_cache_dir_override_and_platform_default(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("SOCLAB_CACHE_DIR", str(tmp_path))
    assert user_cache_dir() == tmp_path
    assert cached_opa_path() == tmp_path / "opa" / OPA_VERSION / opa_asset().executable_name
    monkeypatch.delenv("SOCLAB_CACHE_DIR")
    default = user_cache_dir()
    assert default.name in {"Cache", "soclab"}
    assert "soclab" in default.parts


# ----------------------------------------------------------------- install and verify
def test_install_writes_verified_binary_and_is_idempotent(
    cache: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _pin_digest(monkeypatch, GOOD_BYTES)
    calls: list[str] = []

    def fake_download(url: str, destination: Path) -> None:
        calls.append(url)
        destination.write_bytes(GOOD_BYTES)

    monkeypatch.setattr(opa_binary, "download_to_file", fake_download)
    lines: list[str] = []
    installed = install_opa(echo=lines.append)
    assert installed == cached_opa_path()
    assert installed.read_bytes() == GOOD_BYTES
    assert calls == [opa_asset().url]
    assert not installed.with_name(installed.name + ".part").exists()
    assert any(line.startswith("Downloading https://github.com/open-policy-agent/opa/") for line in lines)
    assert any(opa_asset().sha256 in line for line in lines)
    if sys.platform != "win32":
        assert installed.stat().st_mode & stat.S_IXUSR
    # Second call: digest matches, nothing downloaded.
    again = install_opa(echo=lines.append)
    assert again == installed and calls == [opa_asset().url]
    assert lines[-1].startswith(f"OPA {OPA_VERSION} already installed")


def test_tampered_download_is_rejected_and_not_cached(cache: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _pin_digest(monkeypatch, GOOD_BYTES)

    def tampered(url: str, destination: Path) -> None:
        destination.write_bytes(GOOD_BYTES + b"\x00")

    monkeypatch.setattr(opa_binary, "download_to_file", tampered)
    with pytest.raises(OpaChecksumError, match="sha256 mismatch"):
        install_opa()
    target = cached_opa_path()
    assert not target.exists()
    assert not target.with_name(target.name + ".part").exists()
    assert find_opa_binary() is None


def test_corrupt_cached_binary_is_replaced(cache: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _pin_digest(monkeypatch, GOOD_BYTES)
    target = cached_opa_path()
    target.parent.mkdir(parents=True)
    target.write_bytes(b"stale")
    monkeypatch.setattr(opa_binary, "download_to_file", lambda _u, d: d.write_bytes(GOOD_BYTES))
    assert install_opa().read_bytes() == GOOD_BYTES


# ----------------------------------------------------------------- lookup order
def test_lookup_order_env_then_path_then_cache(
    cache: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    assert find_opa_binary() is None

    cached = cached_opa_path()
    cached.parent.mkdir(parents=True)
    cached.write_bytes(GOOD_BYTES)
    assert find_opa_binary() == cached

    on_path = tmp_path / "bin" / "opa"
    on_path.parent.mkdir()
    on_path.write_bytes(GOOD_BYTES)
    monkeypatch.setattr(opa_binary.shutil, "which", lambda _name: str(on_path))
    assert find_opa_binary() == on_path

    from_env = tmp_path / "custom" / "opa"
    from_env.parent.mkdir()
    from_env.write_bytes(GOOD_BYTES)
    monkeypatch.setenv("SOCLAB_OPA_BINARY", str(from_env))
    assert find_opa_binary() == from_env

    # An env value that does not exist is ignored rather than trusted.
    monkeypatch.setenv("SOCLAB_OPA_BINARY", str(tmp_path / "missing"))
    assert find_opa_binary() == on_path
    assert os.environ["SOCLAB_OPA_BINARY"].endswith("missing")
