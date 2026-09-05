"""Versioned scenario definitions loaded from YAML.

Every attack scenario carries its scoring family, a difficulty tier, and
references to MITRE ATLAS techniques and the OWASP Top 10 for LLM Applications
(2025). The references are labels for the reader and the report; nothing in a
scenario file is executed (ADR 0004).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import Field, field_validator

from soclab.contracts import StrictModel
from soclab.data import scenario_dir
from soclab.scoring import SCORING_FAMILIES

# Bundled with the package; SOCLAB_SCENARIO_DIR overrides it (see soclab.data).
SCENARIO_DIR = scenario_dir()

Difficulty = Literal["low", "medium", "high"]
DIFFICULTIES: tuple[str, ...] = ("low", "medium", "high")


class ProviderSpec(StrictModel):
    behavior: str = "grounded"
    model: str = "mock-investigator-v1"
    script: dict[str, dict[str, Any]] = Field(default_factory=dict)
    cost_per_call_usd: float = Field(default=0.0, ge=0.0)


class HarnessSpec(StrictModel):
    """Attacks the harness performs against the control plane after or around the investigation."""

    forge_grant: bool = False
    tamper_evidence: bool = False
    approve_then_replay: bool = False
    mutate_after_grant: bool = False


class LimitSpec(StrictModel):
    max_calls: int | None = None
    max_cost_usd: float | None = None


class PayloadSpec(StrictModel):
    """Where the untrusted payload lives and, if it is optional, which fixture injection carries it."""

    location: str
    fixture_flag: str | None = None
    injection: str | None = None


class ForbiddenResult(StrictModel):
    tool: str
    target: str | None = None


class Oracle(StrictModel):
    attack_succeeded_if: str
    leaked_if: str | None = None


class AtlasReference(StrictModel):
    id: str = Field(pattern=r"^AML\.T\d{4}(\.\d{3})?$")
    name: str = Field(min_length=1)


class OwaspReference(StrictModel):
    id: str = Field(pattern=r"^LLM(0[1-9]|10)$")
    name: str = Field(min_length=1)


class AttackScenario(StrictModel):
    id: str = Field(pattern=r"^ATK-\d{3}$")
    version: str
    attack_class: str
    title: str
    description: str
    family: str
    difficulty: Difficulty
    atlas: tuple[AtlasReference, ...] = Field(min_length=1)
    owasp_llm: tuple[OwaspReference, ...] = Field(min_length=1)
    untrusted_payload: PayloadSpec | None = None
    provider: ProviderSpec = ProviderSpec()
    harness: HarnessSpec = HarnessSpec()
    limits: LimitSpec = LimitSpec()
    expected_control: str
    forbidden_result: ForbiddenResult | None = None
    oracle: Oracle

    @field_validator("family")
    @classmethod
    def _family_is_a_scoring_family(cls, value: str) -> str:
        if value not in SCORING_FAMILIES:
            msg = f"family must be one of {SCORING_FAMILIES}, got {value!r}"
            raise ValueError(msg)
        return value


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
