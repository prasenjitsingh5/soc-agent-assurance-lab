from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from pydantic import ValidationError

from soclab.contracts import (
    ActionProposal,
    ApprovalDecision,
    ApprovalRecord,
    CanonicalModelEvent,
    DecisionOutcome,
    EvidenceRef,
    FinishReason,
    Obligation,
    PolicyDecision,
    ProviderCapabilities,
    RiskTier,
    TokenUsage,
    TrustLabel,
)

HASH = "a" * 64


def evidence(incident: str = "INC-1001") -> EvidenceRef:
    return EvidenceRef(
        evidence_id="ev-1",
        source_tool="search_siem_events",
        incident_id=incident,
        trust=TrustLabel.UNTRUSTED,
        content_hash=HASH,
        summary="impossible travel between two logins",
    )


def proposal(**overrides: object) -> ActionProposal:
    base: dict[str, object] = {
        "agent_id": "soc-investigator",
        "delegated_user_id": "analyst-1",
        "incident_id": "INC-1001",
        "tool_name": "revoke_sessions",
        "arguments": {"user_id": "u-42"},
        "evidence_refs": (evidence(),),
        "rationale": "credential compromise likely",
        "provider": "mock",
        "model": "mock-investigator-v1",
        "trace_id": "trace-1",
    }
    base.update(overrides)
    return ActionProposal(**base)  # type: ignore[arg-type]


# ----------------------------------------------------------------- ActionProposal
def test_action_requires_incident_and_evidence() -> None:
    with pytest.raises(ValidationError):
        ActionProposal(agent_id="soc-investigator", tool_name="disable_account", arguments={})  # type: ignore[call-arg]


def test_action_rejects_empty_evidence() -> None:
    with pytest.raises(ValidationError, match="at least 1"):
        proposal(evidence_refs=())


def test_action_rejects_evidence_from_other_incident() -> None:
    with pytest.raises(ValidationError, match="belong to the proposal's incident"):
        proposal(evidence_refs=(evidence("INC-OTHER"),))


def test_action_rejects_unknown_fields_and_naive_timestamps() -> None:
    with pytest.raises(ValidationError, match="extra"):
        proposal(executor_handle="nope")
    with pytest.raises(ValidationError, match="timezone-aware"):
        proposal(created_at=datetime(2026, 9, 4, 12, 0))


def test_action_is_immutable_and_round_trips() -> None:
    p = proposal()
    with pytest.raises(ValidationError):
        p.tool_name = "disable_account"  # type: ignore[misc]
    restored = ActionProposal.model_validate_json(p.model_dump_json())
    assert restored == p
    assert restored.created_at.tzinfo is not None


def test_tool_name_must_be_snake_case() -> None:
    with pytest.raises(ValidationError):
        proposal(tool_name="Disable Account")


# ----------------------------------------------------------------- PolicyDecision
def test_decision_outcomes_are_exactly_four() -> None:
    assert [o.value for o in DecisionOutcome] == [
        "allow",
        "allow_with_obligations",
        "require_approval",
        "deny",
    ]
    with pytest.raises(ValidationError):
        PolicyDecision(
            proposal_id=uuid4(),
            outcome="permit",  # type: ignore[arg-type]
            reason_codes=("x",),
            risk_tier=RiskTier.LOW,
            policy_version="1",
            explanation="e",
        )


def test_obligations_consistency() -> None:
    common = {
        "proposal_id": uuid4(),
        "reason_codes": ("r",),
        "risk_tier": RiskTier.LOW,
        "policy_version": "1",
        "explanation": "e",
    }
    with pytest.raises(ValidationError, match="requires at least one obligation"):
        PolicyDecision(outcome=DecisionOutcome.ALLOW_WITH_OBLIGATIONS, **common)  # type: ignore[arg-type]
    with pytest.raises(ValidationError, match="cannot carry obligations"):
        PolicyDecision(outcome=DecisionOutcome.DENY, obligations=(Obligation(name="redact"),), **common)  # type: ignore[arg-type]
    ok = PolicyDecision(
        outcome=DecisionOutcome.ALLOW_WITH_OBLIGATIONS,
        obligations=(Obligation(name="redact_fields", parameters={"fields": ["token"]}),),
        **common,  # type: ignore[arg-type]
    )
    assert ok.obligations[0].parameters == {"fields": ["token"]}


def test_decision_requires_reason_code() -> None:
    with pytest.raises(ValidationError):
        PolicyDecision(
            proposal_id=uuid4(),
            outcome=DecisionOutcome.DENY,
            reason_codes=(),
            risk_tier=RiskTier.HIGH,
            policy_version="1",
            explanation="e",
        )


# ----------------------------------------------------------------- ApprovalRecord
def test_approval_expiry_and_validity() -> None:
    now = datetime.now(tz=UTC)
    with pytest.raises(ValidationError, match="after decided_at"):
        ApprovalRecord(
            proposal_id=uuid4(),
            approver_id="lead",
            decision=ApprovalDecision.APPROVED,
            reason="ok",
            decided_at=now,
            expires_at=now,
        )
    rec = ApprovalRecord(
        proposal_id=uuid4(),
        approver_id="lead",
        decision=ApprovalDecision.APPROVED,
        reason="confirmed with user",
        decided_at=now,
        expires_at=now + timedelta(minutes=10),
    )
    assert rec.is_valid_at(now + timedelta(minutes=5))
    assert not rec.is_valid_at(now + timedelta(minutes=10))
    rejected = rec.model_copy(update={"decision": ApprovalDecision.REJECTED})
    assert not rejected.is_valid_at(now)


# ----------------------------------------------------------------- Capabilities and events
def test_capabilities_are_explicit_booleans() -> None:
    caps = ProviderCapabilities(
        tool_calling=True, structured_output=False, streaming=True, usage_reporting=True
    )
    assert caps.multimodal_input is False
    with pytest.raises(ValidationError):
        ProviderCapabilities(tool_calling=True, structured_output=False, streaming=True)  # type: ignore[call-arg]


def test_canonical_event_arguments_require_tool() -> None:
    usage = TokenUsage(input_tokens=10, output_tokens=5, estimated=False)
    assert usage.total_tokens == 15
    base = {
        "trace_id": "t",
        "run_id": uuid4(),
        "incident_id": "INC-1001",
        "agent_id": "a",
        "delegated_user_id": "u",
        "provider": "mock",
        "model": "m",
        "finish_reason": FinishReason.TOOL_PROPOSAL,
        "usage": usage,
        "latency_ms": 12,
    }
    with pytest.raises(ValidationError, match="require a proposed_tool"):
        CanonicalModelEvent(validated_arguments={"user_id": "u-42"}, **base)  # type: ignore[arg-type]
    event = CanonicalModelEvent(
        proposed_tool="get_identity_profile", validated_arguments={"user_id": "u-42"}, **base
    )  # type: ignore[arg-type]
    assert event.cost_is_estimated is True
    assert CanonicalModelEvent.model_validate_json(event.model_dump_json()) == event
