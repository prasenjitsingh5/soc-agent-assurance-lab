"""The executive summary reads every figure from the scorecard and renders as plain text."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

import pytest

from soclab.evidence import EvidenceRepository
from soclab.reports import (
    ReportAudience,
    ReportGenerator,
    render_text,
    report_timestamp,
    summary_from_payload,
    summary_from_report,
)
from soclab.scoring import GATE_NAMES, AssuranceResult, CampaignResult, score_campaign

FIXED = datetime(2026, 9, 5, 12, 0, tzinfo=UTC)
ScorecardBuilder = Callable[[CampaignResult], tuple[dict[str, Any], EvidenceRepository]]


def test_summary_reads_every_field_from_the_scorecard(clean_scorecard: dict[str, Any]) -> None:
    assurance = AssuranceResult.model_validate(clean_scorecard["assurance"])
    summary = summary_from_payload(clean_scorecard, generated_at=FIXED)
    assert summary.campaign_id == str(assurance.campaign_id)
    assert (summary.provider, summary.model, summary.mode) == ("mock", "mock-investigator-v1", "protected")
    assert summary.date_label == "2026-09-05 12:00 UTC"
    assert summary.sample_count == 3
    assert summary.authority_level == assurance.recommended_authority_level.value
    assert summary.authority_label == "Act with approval"
    assert tuple(g.name for g in summary.gates) == GATE_NAMES
    assert all(g.passed for g in summary.gates) and summary.failed_gates == ()
    assert len(summary.families) == 5
    for row, family in zip(summary.families, assurance.families, strict=True):
        assert row.score == family.value and row.weight == family.weight
        assert row.components[0].startswith(family.components[0].name.replace("_", " "))
    assert (summary.attack_successes, summary.attack_success_rate) == (0, 0.0)
    assert summary.attack_success_ci95 == assurance.attack_success_ci95
    assert summary.control_change is not None
    assert summary.control_change.baseline_attack_success == pytest.approx(2 / 3, abs=1e-3)
    assert summary.all_chains_valid is True
    assert len(summary.chain_heads) == 3
    assert all(head.root_hash and len(head.root_hash) == 64 for head in summary.chain_heads)
    assert dict(clean_scorecard["audit_roots"]) == {h.run_id: h.root_hash for h in summary.chain_heads}
    assert "No mandatory gate failed" in summary.decision_statement


def test_failed_gate_drives_the_decision(failed_scorecard: dict[str, Any]) -> None:
    summary = summary_from_payload(failed_scorecard, generated_at=FIXED)
    assert summary.authority_level == "L1"
    assert summary.failed_gates == ("sensitive_data_leakage",)
    assert summary.decision_statement.startswith("Mandatory gate failed: sensitive_data_leakage")
    assert summary.critical_failures == ("ATK-001",)
    assert summary.attack_successes == 1 and summary.control_change is None


def test_summary_from_report_matches_payload(
    clean_campaign: CampaignResult, scorecard_builder: ScorecardBuilder
) -> None:
    payload, repo = scorecard_builder(clean_campaign)
    report = ReportGenerator(repo).generate(
        clean_campaign, score_campaign(clean_campaign), ReportAudience.EXECUTIVE
    )
    assert summary_from_report(report, generated_at=FIXED) == summary_from_payload(
        payload, generated_at=FIXED
    )


def test_render_text_contains_the_key_fields(clean_scorecard: dict[str, Any]) -> None:
    summary = summary_from_payload(clean_scorecard, generated_at=FIXED)
    text = render_text(summary)
    assert text.startswith("Executive assurance summary\n")
    assert f"Campaign      {summary.campaign_id}" in text
    assert "Provider      mock / mock-investigator-v1" in text
    assert "Date          2026-09-05 12:00 UTC" in text
    assert "Recommended authority level: L4 Act with approval" in text
    for gate in GATE_NAMES:
        assert f"{gate.replace('_', ' '):<28} pass" in text
    assert "security resilience" in text and "economic efficiency" in text
    assert "Attack success 0 of 3 (0%), 95% interval 0% to 56%" in text
    assert "Baseline to protected: attack success 67% to 0%" in text
    assert "Evidence chain: 3 runs, verified" in text
    assert summary.chain_heads[0].root_hash in text
    assert "synthetic scenarios" in text


def test_render_text_caps_the_chain_heads(clean_scorecard: dict[str, Any]) -> None:
    summary = summary_from_payload(clean_scorecard, generated_at=FIXED)
    heads = tuple(summary.chain_heads[0].model_copy(update={"run_id": f"run-{i}"}) for i in range(20))
    text = render_text(summary.model_copy(update={"chain_heads": heads}))
    assert "run-11" in text and "run-12" not in text
    assert "and 8 more; see the technical report" in text


def test_report_timestamp_honours_source_date_epoch(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SOURCE_DATE_EPOCH", str(int(FIXED.timestamp())))
    assert report_timestamp() == FIXED
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "not a number")
    with pytest.raises(ValueError, match="SOURCE_DATE_EPOCH"):
        report_timestamp()
    monkeypatch.delenv("SOURCE_DATE_EPOCH")
    assert report_timestamp().tzinfo is UTC
