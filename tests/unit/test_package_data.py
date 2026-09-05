"""An installed wheel must carry every file the CLI reads at runtime."""

from __future__ import annotations

import tomllib
from pathlib import Path

import pytest

from soclab.data import bundled_path, policy_dir, scenario_dir
from soclab.evaluator import load_attack_scenarios
from soclab.evaluator.scenarios import load_incident

REPO = Path(__file__).resolve().parents[2]
PACKAGE = REPO / "soclab"


def test_bundled_data_resolves_inside_the_package() -> None:
    assert scenario_dir() == PACKAGE / "data" / "scenarios"
    assert policy_dir() == PACKAGE / "data" / "policies"
    assert (policy_dir() / "soc_authorization.rego").is_file()
    assert len(load_attack_scenarios()) == 30
    assert load_incident().id


def test_environment_overrides_win(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("SOCLAB_SCENARIO_DIR", str(tmp_path / "s"))
    monkeypatch.setenv("SOCLAB_POLICY_DIR", str(tmp_path / "p"))
    assert scenario_dir() == tmp_path / "s"
    assert policy_dir() == tmp_path / "p"
    assert bundled_path("scenarios") == PACKAGE / "data" / "scenarios"


def test_every_runtime_file_matches_a_package_data_pattern() -> None:
    """Guards against adding a fixture, template, scenario or policy that the wheel would not ship."""
    with (REPO / "pyproject.toml").open("rb") as handle:
        package_data: dict[str, list[str]] = tomllib.load(handle)["tool"]["setuptools"]["package-data"]
    shipped: set[Path] = set()
    for package, patterns in package_data.items():
        base = PACKAGE.joinpath(*package.split(".")[1:])
        for pattern in patterns:
            shipped.update(p.resolve() for p in base.glob(pattern))
    runtime_files = {
        p.resolve()
        for folder in ("data", "simulator/fixtures", "reports/templates")
        for p in (PACKAGE / folder).rglob("*")
        if p.is_file() and p.suffix != ".py" and "__pycache__" not in p.parts
    }
    missing = sorted(str(p.relative_to(PACKAGE)) for p in runtime_files - shipped)
    assert not missing, f"not covered by [tool.setuptools.package-data]: {missing}"
