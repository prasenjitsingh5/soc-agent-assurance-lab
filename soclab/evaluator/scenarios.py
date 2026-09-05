"""Versioned scenario definitions loaded from YAML."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import Field

from soclab.contracts import StrictModel
from soclab.data import scenario_dir

# Bundled with the package; SOCLAB_SCENARIO_DIR overrides it (see soclab.data).
SCENARIO_DIR = scenario_dir()


class ProviderSpec(StrictModel):
    behavior: str = "grounded"
    model: str = "mock-investigator-v1"
    script: dict[str, dict[str, Any]] = Field(default_factory=dict)


class HarnessSpec(StrictModel):
    forge_grant: bool = False


class LimitSpec(StrictModel):
    max_calls: int | None = None
    max_cost_usd: float | None = None


class ForbiddenResult(StrictModel):
    tool: str
    target: str | None = None


class Oracle(StrictModel):
    attack_succeeded_if: str
    leaked_if: str | None = None


class AttackScenario(StrictModel):
    id: str = Field(pattern=r"^ATK-\d{3}$")
    version: str
    attack_class: str
    title: str
    description: str
    untrusted_payload: dict[str, Any] | None = None
    provider: ProviderSpec = ProviderSpec()
    harness: HarnessSpec = HarnessSpec()
    limits: LimitSpec = LimitSpec()
    expected_control: str
    forbidden_result: ForbiddenResult | None = None
    oracle: Oracle


class IncidentScenario(StrictModel):
    id: str
    version: str
    title: str
    fixture: str
    subject_user_id: str
    expected_techniques: tuple[str, ...]
    expected_recommendation: str
    alert_sources: tuple[str, ...]


def load_incident(name: str = "identity-compromise") -> IncidentScenario:
    with (SCENARIO_DIR / "incidents" / f"{name}.yaml").open(encoding="utf-8") as handle:
        return IncidentScenario.model_validate(yaml.safe_load(handle))


def load_attack_scenarios(directory: Path | None = None) -> tuple[AttackScenario, ...]:
    folder = directory or SCENARIO_DIR / "attacks"
    scenarios = []
    for path in sorted(folder.glob("ATK-*.yaml")):
        with path.open(encoding="utf-8") as handle:
            scenarios.append(AttackScenario.model_validate(yaml.safe_load(handle)))
    return tuple(scenarios)
