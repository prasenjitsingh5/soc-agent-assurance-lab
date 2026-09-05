"""Locate or install the Open Policy Agent binary.

The lab pins one OPA release and hard codes the sha256 of each official
build. ``soclab opa install`` downloads the build for the current operating
system and CPU into a per-user cache, verifies the digest and refuses on
mismatch. Nothing is downloaded unless the user runs that command or passes
``--install-opa`` to ``soclab demo``.

Lookup order for :func:`find_opa_binary`:

1. ``SOCLAB_OPA_BINARY``, when it names an existing file.
2. ``opa`` on ``PATH``.
3. The per-user cache written by ``soclab opa install``.
"""

from __future__ import annotations

import hashlib
import os
import platform
import shutil
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import httpx

OPA_VERSION = "1.20.2"
OPA_RELEASE_URL = f"https://github.com/open-policy-agent/opa/releases/download/v{OPA_VERSION}"

# Official release assets and their sha256 digests, copied from the
# ``<asset>.sha256`` files published with
# https://github.com/open-policy-agent/opa/releases/tag/v1.20.2 on 2026-09-05.
# Static builds are used on Linux so the binary runs on musl and glibc alike.
# Bump OPA_VERSION and every digest together.
_ASSETS: dict[tuple[str, str], tuple[str, str]] = {
    ("windows", "amd64"): (
        "opa_windows_amd64.exe",
        "e2f2e2b735ab98f316171ca47a6b352288cdeb5a616e31aa16335b8934748453",
    ),
    ("linux", "amd64"): (
        "opa_linux_amd64_static",
        "69da5179ee403d10fa11bab6cfb4ffb0d23dba5f9b682fa977db772a1da5670f",
    ),
    ("linux", "arm64"): (
        "opa_linux_arm64_static",
        "431bed5a365578241ab06c7cc1c7d0cdff8c11dcbc6f12c3488590deb8b8d66d",
    ),
    ("darwin", "amd64"): (
        "opa_darwin_amd64",
        "e9b8d205db1aeaa6ec350855087b7d7fc014e7728b65cdf822464ee59e63f601",
    ),
    ("darwin", "arm64"): (
        "opa_darwin_arm64",
        "54e7008e696d39e8e4f96594e2b71bcbe45fd9a4f838102bcf1240638bf3fbe1",
    ),
}

_ARCH_ALIASES = {
    "amd64": "amd64",
    "x86_64": "amd64",
    "x64": "amd64",
    "arm64": "arm64",
    "aarch64": "arm64",
}

_CHUNK = 1 << 16


class OpaInstallError(Exception):
    """The binary could not be installed. The cache is left unchanged."""


class OpaChecksumError(OpaInstallError):
    """The downloaded file does not match the pinned sha256."""


@dataclass(frozen=True)
class OpaAsset:
    """One official release build."""

    system: str
    arch: str
    filename: str
    sha256: str

    @property
    def url(self) -> str:
        return f"{OPA_RELEASE_URL}/{self.filename}"

    @property
    def executable_name(self) -> str:
        return "opa.exe" if self.system == "windows" else "opa"


def platform_key(system: str | None = None, machine: str | None = None) -> tuple[str, str]:
    """Normalize ``platform.system()`` and ``platform.machine()`` to OPA's naming."""
    raw_system = (system or platform.system()).lower()
    raw_machine = (machine or platform.machine()).lower()
    if raw_system.startswith("win"):
        raw_system = "windows"
    arch = _ARCH_ALIASES.get(raw_machine, raw_machine)
    return raw_system, arch


def opa_asset(system: str | None = None, machine: str | None = None) -> OpaAsset:
    """The pinned build for a platform. Raises :class:`OpaInstallError` when there is none."""
    key = platform_key(system, machine)
    try:
        filename, digest = _ASSETS[key]
    except KeyError:
        supported = ", ".join(f"{s}/{a}" for s, a in sorted(_ASSETS))
        msg = f"no pinned OPA build for {key[0]}/{key[1]}; supported: {supported}"
        raise OpaInstallError(msg) from None
    return OpaAsset(system=key[0], arch=key[1], filename=filename, sha256=digest)


def user_cache_dir() -> Path:
    """Per-user cache root. ``SOCLAB_CACHE_DIR`` overrides the platform default."""
    override = os.environ.get("SOCLAB_CACHE_DIR")
    if override:
        return Path(override)
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA")
        root = Path(base) if base else Path.home() / "AppData" / "Local"
        return root / "soclab" / "Cache"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Caches" / "soclab"
    xdg = os.environ.get("XDG_CACHE_HOME")
    return (Path(xdg) if xdg else Path.home() / ".cache") / "soclab"


def cached_opa_path(asset: OpaAsset | None = None) -> Path:
    """Where ``soclab opa install`` puts the binary for the pinned version."""
    resolved = asset or opa_asset()
    return user_cache_dir() / "opa" / OPA_VERSION / resolved.executable_name


def find_opa_binary() -> Path | None:
    """Locate opa: ``SOCLAB_OPA_BINARY``, then ``PATH``, then the per-user cache."""
    env = os.environ.get("SOCLAB_OPA_BINARY")
    if env and Path(env).is_file():
        return Path(env)
    found = shutil.which("opa")
    if found:
        return Path(found)
    try:
        cached = cached_opa_path()
    except OpaInstallError:
        return None
    return cached if cached.is_file() else None


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(_CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()


Downloader = Callable[[str, Path], None]


def download_to_file(url: str, destination: Path) -> None:
    """Stream one URL to a file. Follows the GitHub release redirect. No retries."""
    with httpx.stream("GET", url, follow_redirects=True, timeout=120.0) as response:
        response.raise_for_status()
        with destination.open("wb") as handle:
            for chunk in response.iter_bytes(_CHUNK):
                handle.write(chunk)


def install_opa(
    *,
    destination: Path | None = None,
    download: Downloader | None = None,
    echo: Callable[[str], None] | None = None,
) -> Path:
    """Download the pinned OPA build into the cache and verify it.

    Idempotent: a cached file with the pinned digest is reused without any
    network access. A cached file with the wrong digest is replaced. On a
    digest mismatch the partial download is deleted and
    :class:`OpaChecksumError` is raised; the cache never holds an unverified
    binary.
    """
    asset = opa_asset()
    target = destination or cached_opa_path(asset)
    say = echo or (lambda _line: None)
    if target.is_file() and sha256_of(target) == asset.sha256:
        say(f"OPA {OPA_VERSION} already installed at {target}")
        return target
    say(f"Downloading {asset.url}")
    say(f"Expecting sha256 {asset.sha256}")
    target.parent.mkdir(parents=True, exist_ok=True)
    partial = target.with_name(target.name + ".part")
    fetch = download or download_to_file
    try:
        fetch(asset.url, partial)
        actual = sha256_of(partial)
        if actual != asset.sha256:
            msg = f"sha256 mismatch for {asset.filename}: expected {asset.sha256}, got {actual}"
            raise OpaChecksumError(msg)
        if sys.platform != "win32":
            partial.chmod(partial.stat().st_mode | 0o755)
        os.replace(partial, target)
    except httpx.HTTPError as exc:
        msg = f"download failed: {type(exc).__name__}: {exc}"
        raise OpaInstallError(msg) from exc
    finally:
        partial.unlink(missing_ok=True)
    say(f"Installed OPA {OPA_VERSION} at {target}")
    return target
