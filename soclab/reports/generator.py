"""Report generation.

Both audiences read the same :class:`AssuranceResult` and the same evidence
chain. The executive report leads with the decision; the technical report adds
every scenario, decision, approval, receipt and the chain verification. Neither
report ever computes a number the scoring engine did not already record.
"""

from __future__ import annotations

import html
import json
from enum import StrEnum
from pathlib import Path
from typing import Any
from uuid import UUID

from jinja2 import Environment, FileSystemLoader, select_autoescape

from soclab.contracts import StrictModel
from soclab.evidence import EvidenceRepository
from soclab.redaction import DEFAULT_PATTERNS, redact_secrets
from soclab.scoring import AssuranceResult, CampaignResult

TEMPLATE_DIR = Path(__file__).parent / "templates"


class ReportAudience(StrEnum):
    EXECUTIVE = "executive"
    TECHNICAL = "technical"


class GeneratedReport(StrictModel):
    audience: ReportAudience
    campaign_id: UUID
    html: str
    json_payload: str
    audit_roots: dict[str, str | None]
    all_chains_valid: bool


def comparison_table(results: list[AssuranceResult]) -> list[dict[str, Any]]:
    """Rows for a side-by-side comparison across modes or providers."""
    rows = []
    for r in results:
        rows.append(
            {
                "label": f"{r.provider}/{r.model} ({r.mode})",
                "composite": round(r.composite, 3),
                "attack_success_rate": round(r.attack_success_rate.value, 3),
                "ci95": [round(x, 3) for x in r.attack_success_ci95],
                "false_block_rate": round(r.false_block_rate.value, 3),
                "gate_failures": list(r.gate_failures),
                "authority": r.recommended_authority_level.value,
                "sample_count": r.sample_count,
                "cost_is_estimated": r.cost_is_estimated,
            }
        )
    return rows


class ReportGenerator:
    def __init__(
        self, repository: EvidenceRepository, *, patterns: tuple[str, ...] = DEFAULT_PATTERNS
    ) -> None:
        self._repository = repository
        self._patterns = patterns
        self._env = Environment(
            loader=FileSystemLoader(str(TEMPLATE_DIR)),
            autoescape=select_autoescape(["html", "j2"], default_for_string=True, default=True),
        )

    def _chains(self, campaign: CampaignResult) -> tuple[dict[str, str | None], bool, list[dict[str, Any]]]:
        roots: dict[str, str | None] = {}
        valid = True
        details = []
        for outcome in campaign.outcomes:
            verification = self._repository.verify_chain(outcome.run_id)
            roots[str(outcome.run_id)] = verification.root_hash
            valid = valid and verification.valid
            details.append(
                {
                    "run_id": str(outcome.run_id),
                    "scenario_id": outcome.scenario_id,
                    "valid": verification.valid,
                    "length": verification.length,
                    "root_hash": verification.root_hash,
                    "first_invalid_sequence": verification.first_invalid_sequence,
                }
            )
        return roots, valid, details

    def _decisions(self, campaign: CampaignResult) -> list[dict[str, Any]]:
        rows = []
        for outcome in campaign.outcomes:
            for event in self._repository.events_for(outcome.run_id):
                if event.event_type in {
                    "gateway.policy_decision",
                    "gateway.approval_requested",
                    "gateway.executed",
                    "gateway.execution_refused",
                    "gateway.policy_unavailable",
                    "execution.receipt",
                }:
                    rows.append(
                        {
                            "scenario_id": outcome.scenario_id,
                            "sequence": event.sequence,
                            "type": event.event_type,
                            "detail": json.dumps(
                                redact_secrets(event.payload.get("detail", event.payload), self._patterns),
                                sort_keys=True,
                            )[:300],
                        }
                    )
        return rows

    def generate(
        self,
        campaign: CampaignResult,
        assurance: AssuranceResult,
        audience: ReportAudience,
        *,
        comparison: list[AssuranceResult] | None = None,
        baseline: AssuranceResult | None = None,
    ) -> GeneratedReport:
        roots, valid, chain_details = self._chains(campaign)
        control_change = None
        if baseline is not None:
            control_change = {
                "baseline_attack_success": round(baseline.attack_success_rate.value, 3),
                "protected_attack_success": round(assurance.attack_success_rate.value, 3),
                "baseline_composite": round(baseline.composite, 3),
                "protected_composite": round(assurance.composite, 3),
            }
        context: dict[str, Any] = {
            "assurance": assurance,
            "campaign": campaign,
            "audience": audience.value,
            "audit_roots": roots,
            "all_chains_valid": valid,
            "chain_details": chain_details,
            "comparison": comparison_table(comparison or [assurance]),
            "control_change": control_change,
            "decisions": self._decisions(campaign) if audience is ReportAudience.TECHNICAL else [],
            "outcomes": [o.model_dump(mode="json") for o in campaign.outcomes]
            if audience is ReportAudience.TECHNICAL
            else [],
            "families": [f.model_dump(mode="json") for f in assurance.families],
        }
        template = self._env.get_template(f"{audience.value}.html.j2")
        rendered = template.render(**context)
        payload = {
            "audience": audience.value,
            "campaign_id": str(campaign.campaign_id),
            "assurance": assurance.model_dump(mode="json"),
            "audit_roots": roots,
            "all_chains_valid": valid,
            "control_change": control_change,
            "comparison": context["comparison"],
        }
        return GeneratedReport(
            audience=audience,
            campaign_id=campaign.campaign_id,
            html=redact_secrets(rendered, self._patterns),
            json_payload=json.dumps(redact_secrets(payload, self._patterns), indent=2, sort_keys=True),
            audit_roots=roots,
            all_chains_valid=valid,
        )

    @staticmethod
    def escape(value: str) -> str:
        return html.escape(value)
