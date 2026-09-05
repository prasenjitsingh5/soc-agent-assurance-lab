"""A managed OPA server for local runs and tests.

Spawning ``opa eval`` per decision costs a few hundred milliseconds. For a
campaign of a dozen scenarios with seven decisions each that adds up to
minutes. This module starts ``opa run --server`` once, waits for its health
endpoint, and hands back an :class:`OpaHttpPolicyEngine` bound to it. The
process is stopped on close. It is the same code path the Docker profile uses,
so tests exercise the HTTP client against a real OPA.
"""

from __future__ import annotations

import socket
import subprocess  # noqa: S404  # nosec B404
import time
from pathlib import Path
from types import TracebackType

import httpx

from soclab.policy.client import OPA_NOT_FOUND, POLICY_DIR, OpaHttpPolicyEngine, PolicyUnavailableError
from soclab.policy.opa_binary import find_opa_binary


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        port: int = sock.getsockname()[1]
        return port


class ManagedOpaServer:
    """Context manager that owns one OPA server process."""

    def __init__(
        self, *, binary: Path | None = None, policy_dir: Path = POLICY_DIR, startup_timeout: float = 15.0
    ) -> None:
        resolved = binary or find_opa_binary()
        if resolved is None:
            raise PolicyUnavailableError(OPA_NOT_FOUND)
        self._binary = resolved
        self._policy_dir = policy_dir
        self._timeout = startup_timeout
        self._process: subprocess.Popen[bytes] | None = None
        self.base_url = ""

    def start(self) -> OpaHttpPolicyEngine:
        port = _free_port()
        self.base_url = f"http://127.0.0.1:{port}"
        # Fixed binary path and argument list, no shell, policy directory from the repository.
        self._process = subprocess.Popen(  # noqa: S603  # nosec B603
            [
                str(self._binary),
                "run",
                "--server",
                "--addr",
                f"127.0.0.1:{port}",
                "--log-level",
                "error",
                str(self._policy_dir),
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        deadline = time.monotonic() + self._timeout
        while time.monotonic() < deadline:
            if self._process.poll() is not None:
                msg = f"opa server exited early with code {self._process.returncode}"
                raise PolicyUnavailableError(msg)
            try:
                if httpx.get(self.base_url + "/health", timeout=0.5).status_code == 200:
                    return OpaHttpPolicyEngine(self.base_url)
            except httpx.HTTPError:
                time.sleep(0.1)
        self.stop()
        msg = "opa server did not become healthy in time"
        raise PolicyUnavailableError(msg)

    def stop(self) -> None:
        if self._process is not None and self._process.poll() is None:
            self._process.terminate()
            try:
                self._process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._process.kill()
        self._process = None

    def __enter__(self) -> OpaHttpPolicyEngine:
        return self.start()

    def __exit__(
        self, exc_type: type[BaseException] | None, exc: BaseException | None, tb: TracebackType | None
    ) -> None:
        self.stop()
