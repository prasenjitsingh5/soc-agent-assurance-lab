"""Versioned scenario definitions loaded from YAML.

Two kinds of scenario share one schema. An attack scenario (``ATK-nnn``)
carries its scoring family, a difficulty tier, and references to MITRE ATLAS
techniques and the OWASP Top 10 for LLM Applications (2025). A benign control
(``BEN-nnn``, attack class ``none``) is a legitimate, in-scope request a correct
control plane must allow or route to approval; it names the legitimate action
and the oracle that records a false block when the action is denied. Benign
controls carry no difficulty tier and no technique references. The references
are labels for the reader and the report; nothing in a scenario file is
executed (ADR 0004).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import Field, field_validator, model_validator

from soclab.contracts import StrictModel
from soclab.data import scenario_dir
from soclab.scoring import BENIGN_ATTACK_CLASS, NO_DIFFICULTY, SCORING_FAMILIES

# Bundled with the package; SOCLAB_SCENARIO_DIR overrides it (see soclab.data).
SCENARIO_DIR = scenario_dir()

Difficulty = Literal["low", "medium", "high", "none"]
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

    @property
    def any(self) -> bool:
        return self.forge_grant or self.tamper_evidence or self.approve_then_replay or self.mutate_after_grant


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


class LegitimateAction(StrictModel):
    """The in-scope action a benign control expects the model to propose and the control plane to pass."""

    tool: str
    target: str


class Oracle(StrictModel):
    """Named predicates from ``runner.ORACLES``. Attacks name one kind, benign controls the other."""

    attack_succeeded_if: str | None = None
    false_block_if: str | None = None
    leaked_if: str | None = None


class AtlasReference(StrictModel):
    id: str = Field(pattern=r"^AML\.T\d{4}(\.\d{3})?$")
    name: str = Field(min_length=1)


class OwaspReference(StrictModel):
    id: str = Field(pattern=r"^LLM(0[1-9]|10)$")
    name: str = Field(min_length=1)


class AttackScenario(StrictModel):
    id: str = Field(pattern=r"^(ATK|BEN)-\d{3}$")
    version: str
    attack_class: str
    title: str
    description: str
    family: str
    difficulty: Difficulty
    atlas: tuple[AtlasReference, ...] = ()
    owasp_llm: tuple[OwaspReference, ...] = ()
    untrusted_payload: PayloadSpec | None = None
    provider: ProviderSpec = ProviderSpec()
    harness: HarnessSpec = HarnessSpec()
    limits: LimitSpec = LimitSpec()
    expected_control: str
    forbidden_result: ForbiddenResult | None = None
    legitimate_action: LegitimateAction | None = None
    oracle: Oracle

    @property
    def is_benign(self) -> bool:
        return self.attack_class == BENIGN_ATTACK_CLASS

    @field_validator("family")
    @classmethod
    def _family_is_a_scoring_family(cls, value: str) -> str:
        if value not in SCORING_FAMILIES:
            msg = f"family must be one of {SCORING_FAMILIES}, got {value!r}"
            raise ValueError(msg)
        return value

    @model_validator(mode="after")
    def _kind_is_consistent(self) -> AttackScenario:
        oracle = self.oracle
        if self.is_benign:
            problems = [
                (not self.id.startswith("BEN-"), "a benign control uses a BEN- id"),
                (self.difficulty != NO_DIFFICULTY, f"a benign control has difficulty {NO_DIFFICULTY!r}"),
                (self.legitimate_action is None, "a benign control names its legitimate_action"),
                (oracle.false_block_if is None, "a benign control names oracle.false_block_if"),
                (oracle.attack_succeeded_if is not None, "a benign control has no attack oracle"),
                (self.forbidden_result is not None, "a benign control has no forbidden_result"),
                (self.harness.any, "a benign control performs no harness attack"),
                (self.untrusted_payload is not None, "a benign control carries no untrusted payload"),
            ]
        else:
            problems = [
                (not self.id.startswith("ATK-"), "an attack scenario uses an ATK- id"),
                (self.difficulty not in DIFFICULTIES, f"an attack needs a difficulty in {DIFFICULTIES}"),
                (not self.atlas, "an attack scenario cites at least one ATLAS technique"),
                (not self.owasp_llm, "an attack scenario cites at least one OWASP LLM entry"),
                (oracle.attack_succeeded_if is None, "an attack scenario names oracle.attack_succeeded_if"),
                (oracle.false_block_if is not None, "only a benign control names oracle.false_block_if"),
                (self.legitimate_action is not None, "only a benign control names a legitimate_action"),
            ]
        failed = [message for broken, message in problems if broken]
        if failed:
            msg = f"{self.id}: " + "; ".join(failed)
            raise ValueError(msg)
        return self


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


def _load(folder: Path, pattern: str) -> tuple[AttackScenario, ...]:
    scenarios = []
    for path in sorted(folder.glob(pattern)):
        with path.open(encoding="utf-8") as handle:
            scenarios.append(AttackScenario.model_validate(yaml.safe_load(handle)))
    return tuple(scenarios)


def load_attack_scenarios(directory: Path | None = None) -> tuple[AttackScenario, ...]:
    """The adversarial corpus: every ``ATK-*.yaml`` under ``attacks/``."""
    return _load(directory or SCENARIO_DIR / "attacks", "ATK-*.yaml")


def load_benign_scenarios(directory: Path | None = None) -> tuple[AttackScenario, ...]:
    """The benign control set: every ``BEN-*.yaml`` under ``controls/``."""
    return _load(directory or SCENARIO_DIR / "controls", "BEN-*.yaml")


def load_scenario_corpus() -> tuple[AttackScenario, ...]:
    """Everything a campaign runs: the attacks, then the benign controls."""
    return (*load_attack_scenarios(), *load_benign_scenarios())
