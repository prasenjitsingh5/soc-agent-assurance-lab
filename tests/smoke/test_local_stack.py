"""Clean-start smoke test for the Docker profile. Skipped when Docker is unavailable."""

from __future__ import annotations

import shutil
import subprocess  # noqa: S404  # nosec B404
import time
from pathlib import Path

import httpx
import pytest

REPO = Path(__file__).resolve().parents[2]
COMPOSE = REPO / "infrastructure" / "docker" / "docker-compose.yml"
SECRET = REPO / "infrastructure" / "docker" / "postgres_password.local"


def _docker() -> str | None:
    binary = shutil.which("docker")
    if binary is None:
        return None
    try:
        probe = subprocess.run(  # noqa: S603  # nosec B603
            [binary, "info", "--format", "{{.ServerVersion}}"],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return binary if probe.returncode == 0 and probe.stdout.strip() else None


def _compose(binary: str, *args: str, timeout: int = 600) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603  # nosec B603
        [binary, "compose", "-f", str(COMPOSE), *args],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def test_compose_file_is_valid_yaml_and_pins_images() -> None:
    import yaml

    doc = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
    for name, service in doc["services"].items():
        image = service.get("image", "")
        assert ":" in image and not image.endswith(":latest"), f"{name} must pin an image tag"
        assert "healthcheck" in service, f"{name} needs a healthcheck"
    assert doc["services"]["api"]["ports"] == ["127.0.0.1:8000:8000"]
    assert "read_only" in doc["services"]["api"]


@pytest.mark.smoke
def test_stack_starts_runs_a_campaign_and_verifies_evidence() -> None:
    binary = _docker()
    if binary is None:
        pytest.skip("docker engine not available")
    created_secret = False
    if not SECRET.exists():
        SECRET.write_text("smoke-test-only\n", encoding="utf-8")
        created_secret = True
    try:
        up = _compose(binary, "up", "-d", "--build", "--wait")
        if up.returncode != 0:
            logs = _compose(binary, "logs", "--no-color", "--tail", "80", timeout=60)
            detail = up.stderr[-1500:] + " --- logs --- " + logs.stdout[-4000:]
            pytest.fail("compose up failed: " + detail)
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            try:
                if httpx.get("http://127.0.0.1:8000/health", timeout=2).status_code == 200:
                    break
            except httpx.HTTPError:
                time.sleep(2)
        else:
            pytest.fail("api did not become healthy")
        listing = httpx.get("http://127.0.0.1:8000/api/v1/scenarios", timeout=10)
        assert listing.status_code == 200, listing.text
        created = httpx.post(
            "http://127.0.0.1:8000/api/v1/campaigns",
            json={"mode": "protected", "scenario_ids": ["ATK-001", "ATK-005"]},
            timeout=120,
        )
        if created.status_code != 201:
            logs = _compose(binary, "logs", "--no-color", "--tail", "60", "api", timeout=60)
            pytest.fail("campaign failed: " + created.text + " --- api logs --- " + logs.stdout[-4000:])
        assurance = created.json()["assurance"]
        assert assurance["attack_success_rate"]["value"] == 0.0
        runs = httpx.get("http://127.0.0.1:8000/api/v1/runs", timeout=10).json()
        assert runs and all(r["valid"] for r in runs)
    finally:
        _compose(binary, "down", "-v", timeout=300)
        if created_secret:
            SECRET.unlink(missing_ok=True)
