import json

import pytest

from soclab.evaluator import CampaignConfig, run_campaign
from soclab.evidence import EvidenceRepository
from soclab.policy import OpaHttpPolicyEngine
from soclab.reports import ReportAudience, ReportGenerator
from soclab.scoring import score_campaign


@pytest.fixture
async def completed_runs(opa_engine: OpaHttpPolicyEngine) -> dict[str, object]:
    repo = EvidenceRepository()
    ids = ("ATK-001", "ATK-003", "ATK-005")
    baseline = await run_campaign(
        CampaignConfig(mode="baseline", scenario_ids=ids), policy=None, repository=repo
    )
    protected = await run_campaign(
        CampaignConfig(mode="protected", scenario_ids=ids), policy=opa_engine, repository=repo
    )
    return {"repo": repo, "baseline": baseline, "protected": protected}


@pytest.mark.policy
async def test_report_contains_verifiable_run_identity(completed_runs: dict[str, object]) -> None:
    repo = completed_runs["repo"]
    protected = completed_runs["protected"]
    assert isinstance(repo, EvidenceRepository)
    assurance = score_campaign(protected)  # type: ignore[arg-type]
    report = ReportGenerator(repo).generate(protected, assurance, ReportAudience.EXECUTIVE)  # type: ignore[arg-type]
    assert str(protected.campaign_id) in report.html  # type: ignore[attr-defined]
    for run_id, root in report.audit_roots.items():
        assert root is not None
        assert root in report.html
        assert repo.verify_chain(__import__("uuid").UUID(run_id)).root_hash == root
    assert report.all_chains_valid is True
    payload = json.loads(report.json_payload)
    assert payload["assurance"]["recommended_authority_level"] == assurance.recommended_authority_level.value


@pytest.mark.policy
async def test_executive_report_shows_control_change_and_no_secrets(
    completed_runs: dict[str, object],
) -> None:
    repo = completed_runs["repo"]
    baseline = score_campaign(completed_runs["baseline"])  # type: ignore[arg-type]
    protected = score_campaign(completed_runs["protected"])  # type: ignore[arg-type]
    report = ReportGenerator(repo).generate(  # type: ignore[arg-type]
        completed_runs["protected"],  # type: ignore[arg-type]
        protected,
        ReportAudience.EXECUTIVE,
        baseline=baseline,
        comparison=[baseline, protected],
    )
    assert "What the controls changed" in report.html
    assert "CANARY-SECRET-001" not in report.html
    assert "CANARY-SECRET-001" not in report.json_payload
    assert "Limitations" in report.html
    assert protected.recommended_authority_level.value in report.html


@pytest.mark.policy
async def test_technical_report_lists_decisions_and_outcomes(completed_runs: dict[str, object]) -> None:
    repo = completed_runs["repo"]
    protected = completed_runs["protected"]
    assurance = score_campaign(protected)  # type: ignore[arg-type]
    report = ReportGenerator(repo).generate(protected, assurance, ReportAudience.TECHNICAL)  # type: ignore[arg-type]
    assert "gateway.policy_decision" in report.html
    assert "ATK-001" in report.html and "ATK-005" in report.html
    assert "Audit chain verification" in report.html
    assert "CANARY-SECRET-001" not in report.html


@pytest.mark.policy
async def test_tampered_chain_is_flagged_in_report(completed_runs: dict[str, object]) -> None:
    repo = completed_runs["repo"]
    protected = completed_runs["protected"]
    assert isinstance(repo, EvidenceRepository)
    victim = protected.outcomes[0].run_id  # type: ignore[attr-defined]
    repo.unsafe_modify_for_test(victim, sequence=2, field="tampered", value=True)
    assurance = score_campaign(protected)  # type: ignore[arg-type]
    report = ReportGenerator(repo).generate(protected, assurance, ReportAudience.EXECUTIVE)  # type: ignore[arg-type]
    assert report.all_chains_valid is False
    assert "failed verification" in report.html
