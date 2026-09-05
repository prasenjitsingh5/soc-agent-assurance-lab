"""Scorecards for the summary tests, built the way the CLI builds them: scored campaign plus real chains."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any
from uuid import uuid4

import pytest

from soclab.evidence import AuditEvent, EvidenceRepository
from soclab.reports import ReportAudience, ReportGenerator
from soclab.scoring import CampaignResult, ScenarioOutcome, score_campaign


def make_outcome(**overrides: Any) -> ScenarioOutcome:
    base: dict[str, Any] = {
        "scenario_id": "ATK-001",
        "scenario_version": "1.0.0",
        "attack_class": "indirect_prompt_injection",
        "mode": "protected",
        "run_id": uuid4(),
        "provider": "mock",
        "model": "mock-investigator-v1",
        "attack_succeeded": False,
        "leaked_canary": False,
        "approval_bypassed": False,
        "unauthorized_state_change": False,
        "out_of_scope_execution": False,
        "unapproved_model_used": False,
        "claims_total": 3,
        "claims_supported": 2,
        "expected_techniques": ("T1110.001", "T1621"),
        "found_techniques": ("T1110.001",),
        "recommended_tool": "revoke_sessions",
        "expected_tool": "revoke_sessions",
        "tool_calls_total": 6,
        "tool_calls_valid": 4,
        "completed": True,
        "false_block": False,
        "decisions_total": 4,
        "decisions_recorded": 4,
        "audit_chain_valid": True,
        "latency_ms": 1200,
        "cost_usd": 0.5,
        "cost_is_estimated": True,
        "tokens_total": 800,
    }
    base.update(overrides)
    return ScenarioOutcome(**base)


def make_campaign(outcomes: tuple[ScenarioOutcome, ...], mode: str = "protected") -> CampaignResult:
    return CampaignResult(
        campaign_id=uuid4(),
        mode=mode,
        provider="mock",
        model="mock-investigator-v1",
        policy_version="2026.09.04-1",
        fixture_version="1.0.0",
        prompt_version="1.0.0",
        outcomes=outcomes,
    )


def scorecard_for(
    campaign: CampaignResult, *, baseline: CampaignResult | None = None
) -> tuple[dict[str, Any], EvidenceRepository]:
    """Executive scorecard with a two-event chain per run, so every root hash is real."""
    repo = EvidenceRepository()
    for outcome in campaign.outcomes:
        repo.append_event(AuditEvent(run_id=outcome.run_id, event_type="run.started", payload={"s": 1}))
        repo.append_event(AuditEvent(run_id=outcome.run_id, event_type="run.completed", payload={"s": 2}))
    assurance = score_campaign(campaign)
    base = score_campaign(baseline) if baseline else None
    report = ReportGenerator(repo).generate(
        campaign,
        assurance,
        ReportAudience.EXECUTIVE,
        baseline=base,
        comparison=[base, assurance] if base else None,
    )
    return json.loads(report.json_payload), repo


@pytest.fixture
def scorecard_builder() -> Callable[[CampaignResult], tuple[dict[str, Any], EvidenceRepository]]:
    return scorecard_for


@pytest.fixture
def clean_campaign() -> CampaignResult:
    return make_campaign(
        tuple(make_outcome(scenario_id=f"ATK-00{i}", attack_class=f"class_{i}") for i in (1, 2, 3))
    )


@pytest.fixture
def clean_scorecard(clean_campaign: CampaignResult) -> dict[str, Any]:
    baseline = make_campaign(
        (
            make_outcome(mode="baseline", attack_succeeded=True),
            make_outcome(mode="baseline", scenario_id="ATK-002", attack_succeeded=True, leaked_canary=True),
            make_outcome(mode="baseline", scenario_id="ATK-003"),
        ),
        mode="baseline",
    )
    payload, _ = scorecard_for(clean_campaign, baseline=baseline)
    return payload


@pytest.fixture
def failed_scorecard() -> dict[str, Any]:
    campaign = make_campaign(
        (
            make_outcome(leaked_canary=True, attack_succeeded=True),
            make_outcome(scenario_id="ATK-002"),
        )
    )
    payload, _ = scorecard_for(campaign)
    return payload
