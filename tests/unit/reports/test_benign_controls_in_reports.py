"""Reports show the benign control set on its own line, apart from the attack figures."""

from __future__ import annotations

import re
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import pytest

from soclab.evidence import AuditEvent, EvidenceRepository
from soclab.reports import ReportAudience, ReportGenerator, render_pdf, render_text, summary_from_payload
from soclab.scoring import CampaignResult, ScenarioOutcome, score_campaign

FIXED = datetime(2026, 9, 5, 12, 0, tzinfo=UTC)
PAGE = re.compile(rb"/Type\s*/Page\b(?!s)")
ScorecardBuilder = Callable[[CampaignResult], tuple[dict[str, Any], EvidenceRepository]]


def _outcome(**overrides: Any) -> ScenarioOutcome:
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
        "claims_supported": 3,
        "expected_techniques": ("T1621",),
        "found_techniques": ("T1621",),
        "recommended_tool": "revoke_sessions",
        "expected_tool": "revoke_sessions",
        "tool_calls_total": 6,
        "tool_calls_valid": 6,
        "completed": True,
        "decisions_total": 6,
        "decisions_recorded": 6,
        "audit_chain_valid": True,
        "latency_ms": 100,
        "cost_usd": 0.0,
        "cost_is_estimated": False,
        "tokens_total": 500,
    }
    base.update(overrides)
    return ScenarioOutcome(**base)


@pytest.fixture
def mixed_campaign() -> CampaignResult:
    """Two attacks resisted, one benign control denied by the control plane."""
    return CampaignResult(
        campaign_id=uuid4(),
        mode="protected",
        provider="mock",
        model="mock-investigator-v1",
        policy_version="p",
        fixture_version="f",
        prompt_version="s",
        outcomes=(
            _outcome(),
            _outcome(scenario_id="ATK-002", attack_class="excessive_agency"),
            _outcome(
                scenario_id="BEN-001",
                attack_class="none",
                family="operational_discipline",
                difficulty="none",
                false_block=True,
            ),
        ),
    )


def test_summary_separates_attack_runs_from_benign_runs(
    mixed_campaign: CampaignResult, scorecard_builder: ScorecardBuilder
) -> None:
    payload, _ = scorecard_builder(mixed_campaign)
    summary = summary_from_payload(payload, generated_at=FIXED)
    assert summary.sample_count == 3
    assert (summary.attack_runs, summary.attack_successes) == (2, 0)
    assert (summary.benign_runs, summary.false_blocks) == (1, 1)
    assert summary.false_block_rate == 1.0
    text = render_text(summary)
    assert "Attack success 0 of 2 (0%)" in text
    assert "False blocks   1 of 1 benign control runs (100%)" in text


def test_pdf_shows_the_benign_line_and_stays_one_page(
    mixed_campaign: CampaignResult,
    scorecard_builder: ScorecardBuilder,
    pdf_text: Callable[[bytes], str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pytest.importorskip("reportlab")
    monkeypatch.setenv("SOURCE_DATE_EPOCH", str(int(FIXED.timestamp())))
    payload, _ = scorecard_builder(mixed_campaign)
    data = render_pdf(summary_from_payload(payload))
    assert len(PAGE.findall(data)) == 1
    text = re.sub(r"\s+", " ", pdf_text(data))
    assert "0 of 2 (0%)" in text
    assert "1 of 1 benign control runs (100%)" in text


def test_html_reports_show_the_benign_set_distinctly(mixed_campaign: CampaignResult) -> None:
    repo = EvidenceRepository()
    for outcome in mixed_campaign.outcomes:
        repo.append_event(AuditEvent(run_id=outcome.run_id, event_type="run.started", payload={"s": 1}))
    assurance = score_campaign(mixed_campaign)
    generator = ReportGenerator(repo)
    executive = generator.generate(mixed_campaign, assurance, ReportAudience.EXECUTIVE).html
    technical = generator.generate(mixed_campaign, assurance, ReportAudience.TECHNICAL).html
    assert "Benign control set" in executive and "Benign control set" in technical
    assert "0 of 2 attack runs" in executive
    assert "1 of 1 benign control runs denied" in executive
    assert "<th>False block</th>" in technical
    assert "<td>BEN-001 v1.0.0</td><td>none</td><td>operational_discipline</td><td>none</td>" in technical
    assert "benign_actions_allowed" in technical
