"""One-page executive summary.

The summary is built from the JSON scorecard the generator writes, so the CLI
can render it from a file long after the campaign ran and the API can render
it from a cached campaign through the same path. Every figure comes from the
:class:`AssuranceResult` inside the scorecard. Nothing is derived here: the
only confidence interval shown is the one the engine records for the attack
success rate.
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from typing import Any

from pydantic import Field

from soclab.contracts import AuthorityLevel, StrictModel
from soclab.reports.generator import GeneratedReport
from soclab.scoring import GATE_NAMES, AssuranceResult

TITLE = "Executive assurance summary"
MAX_CHAIN_HEADS = 12


class GateResult(StrictModel):
    name: str
    passed: bool


class FamilyRow(StrictModel):
    family: str
    weight: float
    score: float
    components: tuple[str, ...]


class ChainHead(StrictModel):
    run_id: str
    root_hash: str | None


class ControlChange(StrictModel):
    baseline_attack_success: float
    protected_attack_success: float
    baseline_composite: float
    protected_composite: float


class ExecutiveSummary(StrictModel):
    campaign_id: str
    mode: str
    provider: str
    model: str
    generated_at: datetime
    sample_count: int = Field(ge=0)
    authority_level: str
    authority_label: str
    composite: float
    gates: tuple[GateResult, ...]
    critical_failures: tuple[str, ...]
    families: tuple[FamilyRow, ...]
    # Attack figures count attack runs; false block figures count benign control runs.
    attack_runs: int = Field(ge=0)
    attack_successes: int
    attack_success_rate: float
    attack_success_ci95: tuple[float, float]
    benign_runs: int = Field(ge=0)
    false_blocks: int
    false_block_rate: float
    control_change: ControlChange | None
    all_chains_valid: bool
    chain_heads: tuple[ChainHead, ...]
    profile_version: str
    policy_version: str
    fixture_version: str
    prompt_version: str
    cost_is_estimated: bool
    limitations: tuple[str, ...]

    @property
    def failed_gates(self) -> tuple[str, ...]:
        return tuple(g.name for g in self.gates if not g.passed)

    @property
    def decision_statement(self) -> str:
        if self.failed_gates:
            names = ", ".join(self.failed_gates)
            return f"Mandatory gate failed: {names}. The composite score does not matter until this is fixed."
        if self.critical_failures:
            names = ", ".join(self.critical_failures)
            return f"Critical regression: attacks succeeded in protected mode for {names}."
        return "No mandatory gate failed and no attack succeeded against this configuration."

    @property
    def date_label(self) -> str:
        return self.generated_at.astimezone(UTC).strftime("%Y-%m-%d %H:%M UTC")


def report_timestamp() -> datetime:
    """Generation time in UTC.

    ``SOURCE_DATE_EPOCH``, the reproducible-builds convention, pins it. The PDF
    renderer reads the same variable, so one setting fixes the printed date,
    the document metadata and the file bytes.
    """
    raw = os.environ.get("SOURCE_DATE_EPOCH", "").strip()
    if not raw:
        return datetime.now(tz=UTC)
    try:
        return datetime.fromtimestamp(int(raw), tz=UTC)
    except ValueError as exc:
        msg = "SOURCE_DATE_EPOCH must be an integer Unix time"
        raise ValueError(msg) from exc


def authority_label(level: AuthorityLevel) -> str:
    """``L4_ACT_WITH_APPROVAL`` reads as ``Act with approval``."""
    return level.name.split("_", 1)[1].replace("_", " ").capitalize()


def _count(value: float) -> str:
    return str(int(value)) if float(value).is_integer() else f"{value:.2f}"


def _family_rows(assurance: AssuranceResult) -> tuple[FamilyRow, ...]:
    rows = []
    for family in assurance.families:
        rows.append(
            FamilyRow(
                family=family.family.replace("_", " "),
                weight=family.weight,
                score=family.value,
                components=tuple(
                    f"{c.name.replace('_', ' ')} {_count(c.numerator)}/{_count(c.denominator)}"
                    for c in family.components
                ),
            )
        )
    return tuple(rows)


def summary_from_payload(
    payload: dict[str, Any], *, generated_at: datetime | None = None
) -> ExecutiveSummary:
    """Build the summary from a scorecard dict, the parsed form of ``executive.json``."""
    assurance = AssuranceResult.model_validate(payload["assurance"])
    roots: dict[str, str | None] = dict(payload.get("audit_roots") or {})
    raw_change = payload.get("control_change")
    change = ControlChange.model_validate(raw_change) if raw_change else None
    return ExecutiveSummary(
        campaign_id=str(assurance.campaign_id),
        mode=assurance.mode,
        provider=assurance.provider,
        model=assurance.model,
        generated_at=generated_at or report_timestamp(),
        sample_count=assurance.sample_count,
        authority_level=assurance.recommended_authority_level.value,
        authority_label=authority_label(assurance.recommended_authority_level),
        composite=assurance.composite,
        gates=tuple(GateResult(name=name, passed=name not in assurance.gate_failures) for name in GATE_NAMES),
        critical_failures=assurance.critical_failures,
        families=_family_rows(assurance),
        attack_runs=int(assurance.attack_success_rate.denominator),
        attack_successes=int(assurance.attack_success_rate.numerator),
        attack_success_rate=assurance.attack_success_rate.value,
        attack_success_ci95=assurance.attack_success_ci95,
        benign_runs=int(assurance.false_block_rate.denominator),
        false_blocks=int(assurance.false_block_rate.numerator),
        false_block_rate=assurance.false_block_rate.value,
        control_change=change,
        all_chains_valid=bool(payload.get("all_chains_valid", False)),
        chain_heads=tuple(ChainHead(run_id=run_id, root_hash=root) for run_id, root in roots.items()),
        profile_version=assurance.profile_version,
        policy_version=assurance.policy_version,
        fixture_version=assurance.fixture_version,
        prompt_version=assurance.prompt_version,
        cost_is_estimated=assurance.cost_is_estimated,
        limitations=assurance.limitations,
    )


def summary_from_report(report: GeneratedReport, *, generated_at: datetime | None = None) -> ExecutiveSummary:
    return summary_from_payload(json.loads(report.json_payload), generated_at=generated_at)


def _pct(value: float) -> str:
    return f"{value * 100:.0f}%"


def render_text(summary: ExecutiveSummary) -> str:
    """Plain-text form of the one-pager. Needs no optional dependency."""
    lines = [
        TITLE,
        f"Campaign      {summary.campaign_id}",
        f"Provider      {summary.provider} / {summary.model}",
        f"Configuration {summary.mode}, {summary.sample_count} scenario runs",
        f"Date          {summary.date_label}",
        "",
        f"Recommended authority level: {summary.authority_level} {summary.authority_label}",
        summary.decision_statement,
        f"Composite assurance score {summary.composite:.2f}",
        "",
        "Mandatory gates",
    ]
    lines.extend(f"  {g.name.replace('_', ' '):<28} {'pass' if g.passed else 'FAIL'}" for g in summary.gates)
    lines.append("")
    lines.append("Score families")
    for f in summary.families:
        lines.append(f"  {f.family:<24} weight {f.weight:.2f}  score {f.score:.2f}")
        lines.append(f"    {'; '.join(f.components)}")
    lines.append("")
    lines.append("Attack results")
    lines.append(
        f"  Attack success {summary.attack_successes} of {summary.attack_runs} "
        f"({_pct(summary.attack_success_rate)}), 95% interval "
        f"{_pct(summary.attack_success_ci95[0])} to {_pct(summary.attack_success_ci95[1])}"
    )
    lines.append(
        f"  False blocks   {summary.false_blocks} of {summary.benign_runs} benign control runs "
        f"({_pct(summary.false_block_rate)})"
    )
    lines.append(f"  Critical failures {', '.join(summary.critical_failures) or 'none'}")
    if summary.control_change:
        c = summary.control_change
        lines.append(
            f"  Baseline to protected: attack success {_pct(c.baseline_attack_success)} to "
            f"{_pct(c.protected_attack_success)}, composite {c.baseline_composite:.2f} to "
            f"{c.protected_composite:.2f}"
        )
    lines.append("")
    verdict = "verified" if summary.all_chains_valid else "FAILED verification"
    lines.append(f"Evidence chain: {len(summary.chain_heads)} runs, {verdict}")
    for head in summary.chain_heads[:MAX_CHAIN_HEADS]:
        lines.append(f"  {head.run_id} {head.root_hash or 'no events'}")
    if len(summary.chain_heads) > MAX_CHAIN_HEADS:
        lines.append(f"  and {len(summary.chain_heads) - MAX_CHAIN_HEADS} more; see the technical report")
    lines.append("")
    cost = "estimated from list prices" if summary.cost_is_estimated else "provider reported"
    lines.append(f"Cost figures are {cost}.")
    lines.extend(f"Limitation: {note}" for note in summary.limitations)
    lines.append(
        f"Scoring profile {summary.profile_version}, policy {summary.policy_version}, "
        f"fixture {summary.fixture_version}, prompt {summary.prompt_version}."
    )
    lines.append(
        "Every figure is computed from synthetic scenarios and simulated actions. "
        "Nothing here connects to a production system."
    )
    return "\n".join(lines) + "\n"


__all__ = [
    "MAX_CHAIN_HEADS",
    "TITLE",
    "ChainHead",
    "ControlChange",
    "ExecutiveSummary",
    "FamilyRow",
    "GateResult",
    "authority_label",
    "render_text",
    "report_timestamp",
    "summary_from_payload",
    "summary_from_report",
]
