from typing import Any

import pytest
from fastapi.testclient import TestClient

from soclab.api.main import create_app
from soclab.api.state import AppState
from soclab.contracts import ActionProposal, EvidenceRef, TrustLabel
from soclab.evidence import EvidenceRepository
from soclab.policy import OpaHttpPolicyEngine

HASH = "d" * 64


@pytest.fixture
def state() -> AppState:
    return AppState(repository=EvidenceRepository())


@pytest.fixture
def client(state: AppState) -> TestClient:
    return TestClient(create_app(state))


def test_health_and_version(client: TestClient) -> None:
    assert client.get("/health").json() == {"status": "ok"}
    assert "version" in client.get("/api/v1/version").json()


def test_incidents_and_scenarios(client: TestClient) -> None:
    incidents = client.get("/api/v1/incidents").json()
    assert incidents[0]["id"] == "INC-1001"
    detail = client.get("/api/v1/incidents/INC-1001").json()
    assert detail["injected_event_ids"] == ["siem-005"]
    assert client.get("/api/v1/incidents/INC-9").status_code == 404
    scenarios = client.get("/api/v1/scenarios").json()
    assert len(scenarios) >= 12


def test_baseline_campaign_and_reports(client: TestClient) -> None:
    created = client.post(
        "/api/v1/campaigns", json={"mode": "baseline", "scenario_ids": ["ATK-001", "ATK-005"]}
    )
    assert created.status_code == 201, created.text
    cid = created.json()["campaign_id"]
    assert created.json()["assurance"]["recommended_authority_level"] == "L1"
    listing = client.get("/api/v1/campaigns").json()
    assert listing[0]["authority"] == "L1"
    detail = client.get(f"/api/v1/campaigns/{cid}").json()
    assert len(detail["outcomes"]) == 2
    html = client.get(f"/api/v1/campaigns/{cid}/reports/executive")
    assert html.status_code == 200 and "Recommended authority level" in html.text
    assert "CANARY-SECRET-001" not in html.text
    payload = client.get(f"/api/v1/campaigns/{cid}/reports/technical/json").json()
    assert payload["audience"] == "technical"
    assert client.get("/api/v1/campaigns/00000000-0000-0000-0000-000000000000").status_code == 404


def test_runs_and_verification(client: TestClient) -> None:
    client.post("/api/v1/campaigns", json={"mode": "baseline", "scenario_ids": ["ATK-001"]})
    runs = client.get("/api/v1/runs").json()
    assert runs and runs[0]["valid"] is True
    run_id = runs[0]["run_id"]
    events = client.get(f"/api/v1/runs/{run_id}/events").json()
    assert events[0]["event_type"] == "run.started"
    assert client.get(f"/api/v1/runs/{run_id}/verify").json()["valid"] is True


def test_approval_queue(client: TestClient, state: AppState) -> None:
    proposal = ActionProposal(
        agent_id="soc-investigator",
        delegated_user_id="analyst-1",
        incident_id="INC-1001",
        tool_name="disable_account",
        arguments={"user_id": "u-alex-rivera"},
        evidence_refs=(
            EvidenceRef(
                evidence_id="e",
                source_tool="alert",
                incident_id="INC-1001",
                trust=TrustLabel.UNTRUSTED,
                content_hash=HASH,
                summary="s",
            ),
        ),
        rationale="r",
        provider="mock",
        model="mock-investigator-v1",
        trace_id="t",
    )
    pending = state.approvals.request(proposal, ("approval_required_high_impact",))
    listed = client.get("/api/v1/approvals").json()
    assert listed[0]["tool_name"] == "disable_account"
    denied = client.post(
        f"/api/v1/approvals/{pending.approval_id}/decision",
        json={"approver_id": "analyst-1", "decision": "approved", "reason": "self"},
    )
    assert denied.status_code == 403
    ok = client.post(
        f"/api/v1/approvals/{pending.approval_id}/decision",
        json={"approver_id": "soc-lead", "decision": "approved", "reason": "confirmed with user"},
    )
    assert ok.status_code == 200 and ok.json()["approver_id"] == "soc-lead"
    assert client.get("/api/v1/approvals").json() == []
    assert len(client.get("/api/v1/approvals/history").json()) == 1
    gone = client.post(
        f"/api/v1/approvals/{pending.approval_id}/decision",
        json={"approver_id": "soc-lead", "decision": "approved", "reason": "again"},
    )
    assert gone.status_code == 404


def test_protected_campaign_refused_without_policy(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("SOCLAB_OPA_URL", raising=False)
    monkeypatch.setattr("soclab.api.routes.campaigns.find_opa_binary", lambda: None)
    response = client.post("/api/v1/campaigns", json={"mode": "protected", "scenario_ids": ["ATK-001"]})
    assert response.status_code == 503


@pytest.mark.policy
def test_protected_campaign_through_api(
    state: AppState, opa_engine: OpaHttpPolicyEngine, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SOCLAB_OPA_URL", opa_engine._url.removesuffix("/v1/data/soc/authorization/result"))  # noqa: SLF001
    client = TestClient(create_app(state))
    response = client.post(
        "/api/v1/campaigns", json={"mode": "protected", "scenario_ids": ["ATK-001", "ATK-010"]}
    )
    assert response.status_code == 201, response.text
    body: dict[str, Any] = response.json()
    assert body["assurance"]["attack_success_rate"]["value"] == 0.0
