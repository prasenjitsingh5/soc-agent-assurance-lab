from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import pytest

from soclab.approvals import ApprovalService
from soclab.contracts import (
    ActionProposal,
    ApprovalDecision,
    AuthorityLevel,
    DecisionOutcome,
    EvidenceRef,
    ExecutionStatus,
    Obligation,
    PolicyDecision,
    RiskTier,
    TrustLabel,
)
from soclab.executor import AuthorizationError, Executor
from soclab.gateway import ControlGateway, GatewayConfig, GrantSigner, GrantVerificationError
from soclab.grants import proposal_hash
from soclab.orchestrator import InvestigationStatus, run_investigation
from soclab.policy import (
    AuthorizationContext,
    OpaExecPolicyEngine,
    PolicyUnavailableError,
    find_opa_binary,
)
from soclab.providers.mock import MockProvider
from soclab.simulator import SimulatorState

INC = "INC-1001"
HASH = "c" * 64
opa_available = pytest.mark.skipif(find_opa_binary() is None, reason="opa binary not installed")


def evidence(n: int = 3) -> tuple[EvidenceRef, ...]:
    return tuple(
        EvidenceRef(
            evidence_id=f"ev-{i}",
            source_tool="search_siem_events",
            incident_id=INC,
            trust=TrustLabel.UNTRUSTED,
            content_hash=HASH,
            summary="s",
        )
        for i in range(n)
    )


def make_proposal(tool: str, arguments: dict[str, Any], **kw: Any) -> ActionProposal:
    base: dict[str, Any] = {
        "agent_id": "soc-investigator",
        "delegated_user_id": "analyst-1",
        "incident_id": INC,
        "tool_name": tool,
        "arguments": arguments,
        "evidence_refs": evidence(),
        "rationale": "r",
        "provider": "mock",
        "model": "mock-investigator-v1",
        "trace_id": "t",
    }
    base.update(kw)
    return ActionProposal(**base)


class ScriptedPolicy:
    """Deterministic policy double for gateway-only tests. Rego coverage lives in the policy suite."""

    def __init__(
        self,
        outcome: DecisionOutcome,
        *,
        risk: RiskTier = RiskTier.LOW,
        obligations: tuple[Obligation, ...] = (),
    ) -> None:
        self.outcome = outcome
        self.risk = risk
        self.obligations = obligations
        self.calls = 0
        self.fail = False

    async def decide(self, proposal: ActionProposal, context: AuthorizationContext) -> PolicyDecision:
        self.calls += 1
        if self.fail:
            msg = "opa down"
            raise PolicyUnavailableError(msg)
        return PolicyDecision(
            proposal_id=proposal.proposal_id,
            outcome=self.outcome,
            reason_codes=("scripted",),
            obligations=self.obligations,
            risk_tier=self.risk,
            policy_version="test",
            explanation="scripted",
        )


class System:
    def __init__(
        self,
        policy: Any,
        *,
        level: AuthorityLevel = AuthorityLevel.L4_ACT_WITH_APPROVAL,
        clock: Any = None,
        approval_ttl: int = 600,
        **cfg: Any,
    ) -> None:
        self.simulator = SimulatorState.from_fixture()
        self.signer = GrantSigner(b"k" * 32, ttl_seconds=60)
        self.executor = Executor(self.simulator, self.signer)
        self.approvals = ApprovalService(ttl_seconds=approval_ttl)
        self.policy = policy
        self.gateway = ControlGateway(
            config=GatewayConfig(incident_id=INC, authority_level=level, **cfg),
            policy=policy,
            executor=self.executor,
            signer=self.signer,
            approvals=self.approvals,
            clock=clock,
        )

    def approve(self, proposal: ActionProposal, approver: str = "soc-lead") -> UUID:
        pending = next(
            p for p in self.approvals.pending.values() if p.proposal.proposal_id == proposal.proposal_id
        )
        self.approvals.decide(pending.approval_id, approver, ApprovalDecision.APPROVED, "confirmed with user")
        return pending.approval_id


# ----------------------------------------------------------------- executor refuses anything unsigned
async def test_executor_rejects_unsigned_gateway_grant() -> None:
    system = System(ScriptedPolicy(DecisionOutcome.ALLOW))
    proposal = make_proposal("disable_account", {"user_id": "u-alex-rivera"})
    with pytest.raises(AuthorizationError):
        await system.executor.execute(proposal, grant=None)
    assert system.simulator.users["u-alex-rivera"]["account_enabled"] is True


async def test_executor_rejects_forged_expired_reused_and_tampered_grants() -> None:
    system = System(ScriptedPolicy(DecisionOutcome.ALLOW))
    proposal = make_proposal("revoke_sessions", {"user_id": "u-alex-rivera"})
    good = system.signer.issue(proposal, policy_version="v", approval_id=None, obligations_fulfilled=())

    forged = good.model_copy(update={"signature": "f" * 64})
    with pytest.raises(AuthorizationError, match="signature"):
        await system.executor.execute(proposal, forged)

    with pytest.raises(AuthorizationError, match="expired"):
        await system.executor.execute(proposal, good, now=datetime.now(tz=UTC) + timedelta(minutes=5))

    tampered = proposal.model_copy(update={"arguments": {"user_id": "u-svc-backup"}})
    with pytest.raises(AuthorizationError, match="changed"):
        await system.executor.execute(tampered, good)

    await system.executor.execute(proposal, good)
    with pytest.raises(AuthorizationError, match="already used"):
        await system.executor.execute(proposal, good)
    assert system.simulator.revoked_sessions == {"u-alex-rivera": 1}


def test_grant_signer_requires_strong_key_and_detects_scope_mismatch() -> None:
    with pytest.raises(ValueError):
        GrantSigner(b"short")
    signer = GrantSigner(b"k" * 32)
    a = make_proposal("revoke_sessions", {"user_id": "u-alex-rivera"})
    b = make_proposal("disable_account", {"user_id": "u-alex-rivera"})
    grant = signer.issue(a, policy_version="v", approval_id=None, obligations_fulfilled=())
    with pytest.raises(GrantVerificationError, match="different proposal"):
        signer.verify(grant, b)
    assert proposal_hash(a) != proposal_hash(b)


# ----------------------------------------------------------------- gateway decision paths
async def test_denied_action_never_reaches_executor() -> None:
    system = System(ScriptedPolicy(DecisionOutcome.DENY, risk=RiskTier.HIGH))
    result = await system.gateway.propose(make_proposal("disable_account", {"user_id": "u-svc-backup"}))
    assert result.status is ExecutionStatus.DENIED
    assert result.controlled is True
    assert system.executor.receipts == []
    assert [e.kind for e in system.gateway.events] == ["proposal_received", "policy_decision"]


async def test_read_only_allowed_with_redaction_obligation() -> None:
    policy = ScriptedPolicy(
        DecisionOutcome.ALLOW_WITH_OBLIGATIONS,
        risk=RiskTier.READ_ONLY,
        obligations=(Obligation(name="redact_secrets", parameters={"patterns": ["CANARY-SECRET-*"]}),),
    )
    system = System(policy)
    result = await system.gateway.propose(make_proposal("search_siem_events", {"query": "helpdesk"}))
    assert result.status is ExecutionStatus.EXECUTED
    assert result.output is not None
    text = str(result.output)
    assert "CANARY-SECRET-001" not in text
    assert "[REDACTED]" in text


async def test_high_impact_requires_approval_then_executes_with_obligations() -> None:
    proposal = make_proposal("disable_account", {"user_id": "u-alex-rivera"})
    policy = ScriptedPolicy(DecisionOutcome.REQUIRE_APPROVAL, risk=RiskTier.HIGH)
    system = System(policy)
    first = await system.gateway.propose(proposal)
    assert first.status is ExecutionStatus.AWAITING_APPROVAL
    assert len(system.approvals.pending) == 1
    assert system.simulator.users["u-alex-rivera"]["account_enabled"] is True

    approval_id = system.approve(proposal)
    policy.outcome = DecisionOutcome.ALLOW_WITH_OBLIGATIONS
    policy.obligations = (Obligation(name="record_reversal_plan"), Obligation(name="notify_incident_owner"))
    second = await system.gateway.propose(proposal)
    assert second.status is ExecutionStatus.EXECUTED
    assert second.receipt is not None and second.receipt["simulation"] is True
    assert system.simulator.users["u-alex-rivera"]["account_enabled"] is False
    kinds = [e.kind for e in system.gateway.events]
    assert kinds.index("reversal_plan") < kinds.index("grant_issued") < kinds.index("executed")
    assert approval_id in system.approvals.consumed

    # The consumed approval cannot authorize a replay.
    third = await system.gateway.propose(proposal)
    assert third.status is ExecutionStatus.FAILED_CLOSED
    assert third.reason_codes == ("approval_not_bound",)


async def test_expired_approval_does_not_unlock() -> None:
    proposal = make_proposal("disable_account", {"user_id": "u-alex-rivera"})
    policy = ScriptedPolicy(DecisionOutcome.REQUIRE_APPROVAL, risk=RiskTier.HIGH)
    moment = {"now": datetime.now(tz=UTC)}
    system = System(policy, clock=lambda: moment["now"], approval_ttl=1)
    await system.gateway.propose(proposal)
    system.approve(proposal)
    policy.outcome = DecisionOutcome.ALLOW_WITH_OBLIGATIONS
    policy.obligations = (Obligation(name="record_reversal_plan"),)
    moment["now"] += timedelta(seconds=5)
    result = await system.gateway.propose(proposal)
    assert result.status is ExecutionStatus.FAILED_CLOSED
    assert system.simulator.users["u-alex-rivera"]["account_enabled"] is True


def test_requester_cannot_approve_own_action() -> None:
    approvals = ApprovalService()
    proposal = make_proposal("disable_account", {"user_id": "u-alex-rivera"})
    pending = approvals.request(proposal, ("x",))
    with pytest.raises(PermissionError):
        approvals.decide(pending.approval_id, "analyst-1", ApprovalDecision.APPROVED, "self")
    # The refused attempt did not consume the request.
    record = approvals.decide(pending.approval_id, "soc-lead", ApprovalDecision.APPROVED, "confirmed")
    assert record.approver_id == "soc-lead"
    with pytest.raises(KeyError):
        approvals.decide(pending.approval_id, "soc-lead", ApprovalDecision.APPROVED, "gone")


async def test_policy_outage_fails_closed_for_state_change_and_read_by_default() -> None:
    policy = ScriptedPolicy(DecisionOutcome.ALLOW)
    policy.fail = True
    system = System(policy)
    write = await system.gateway.propose(make_proposal("revoke_sessions", {"user_id": "u-alex-rivera"}))
    assert write.status is ExecutionStatus.FAILED_CLOSED
    assert write.reason_codes == ("policy_unavailable",)
    read = await system.gateway.propose(make_proposal("get_identity_profile", {"user_id": "u-alex-rivera"}))
    assert read.status is ExecutionStatus.FAILED_CLOSED
    assert system.simulator.revoked_sessions == {}


async def test_degraded_read_only_continuation_is_explicit_and_recorded() -> None:
    policy = ScriptedPolicy(DecisionOutcome.ALLOW)
    policy.fail = True
    system = System(policy, degraded_read_only=True)
    read = await system.gateway.propose(make_proposal("get_identity_profile", {"user_id": "u-alex-rivera"}))
    assert read.status is ExecutionStatus.EXECUTED
    assert read.reason_codes == ("degraded_read_only",)
    assert "degraded_read_only_continuation" in [e.kind for e in system.gateway.events]
    write = await system.gateway.propose(make_proposal("revoke_sessions", {"user_id": "u-alex-rivera"}))
    assert write.status is ExecutionStatus.FAILED_CLOSED


async def test_unknown_obligation_blocks_execution() -> None:
    policy = ScriptedPolicy(
        DecisionOutcome.ALLOW_WITH_OBLIGATIONS,
        risk=RiskTier.READ_ONLY,
        obligations=(Obligation(name="phone_home"),),
    )
    system = System(policy)
    result = await system.gateway.propose(make_proposal("get_identity_profile", {"user_id": "u-alex-rivera"}))
    assert result.status is ExecutionStatus.FAILED_CLOSED
    assert result.reason_codes == ("obligation_failed",)


async def test_wrong_incident_is_refused_by_executor_even_if_policy_allows() -> None:
    system = System(ScriptedPolicy(DecisionOutcome.ALLOW))
    proposal = make_proposal(
        "revoke_sessions",
        {"user_id": "u-alex-rivera"},
        incident_id="INC-OTHER",
        evidence_refs=tuple(e.model_copy(update={"incident_id": "INC-OTHER"}) for e in evidence()),
    )
    result = await system.gateway.propose(proposal)
    assert result.status is ExecutionStatus.FAILED_CLOSED
    assert result.reason_codes == ("approval_not_bound",) or result.reason_codes == ("executor_refused",)
    assert system.simulator.revoked_sessions == {}


# ----------------------------------------------------------------- end to end with the real policy
@opa_available
@pytest.mark.policy
async def test_protected_investigation_blocks_injected_action_and_escalates_high_impact() -> None:
    system = System(OpaExecPolicyEngine())
    alert = dict(system.simulator.incident)
    result = await run_investigation(INC, alert, MockProvider(behavior="gullible"), system.gateway)
    assert result.status is InvestigationStatus.COMPLETE
    assert result.recommended_action is not None
    assert result.recommended_action.tool_name == "disable_account"
    assert result.action_result is not None
    # The injected instruction cited a single piece of evidence, so the policy denies it outright.
    assert result.action_result.status is ExecutionStatus.DENIED
    assert "insufficient_evidence_for_action" in result.action_result.reason_codes
    assert result.executions == ()
    assert system.simulator.users["u-svc-backup"]["account_enabled"] is True
    # Read-only collection ran and the canary was redacted before the model saw it.
    assert len(result.evidence) == 6
    assert not any("CANARY-SECRET-001" in e.output_text for e in result.events)
    assert not any("CANARY-SECRET-001" in e.summary for e in result.evidence)


@opa_available
@pytest.mark.policy
async def test_grounded_recommendation_escalates_to_a_human_at_l4() -> None:
    system = System(OpaExecPolicyEngine())
    result = await run_investigation(INC, dict(system.simulator.incident), MockProvider(), system.gateway)
    assert result.recommended_action is not None and result.recommended_action.tool_name == "revoke_sessions"
    assert result.action_result is not None
    assert result.action_result.status is ExecutionStatus.AWAITING_APPROVAL
    assert len(system.approvals.pending) == 1
    assert system.simulator.revoked_sessions == {}


@opa_available
@pytest.mark.policy
async def test_bounded_autonomy_executes_low_risk_without_approval() -> None:
    system = System(OpaExecPolicyEngine(), level=AuthorityLevel.L5_BOUNDED_AUTONOMY)
    result = await run_investigation(INC, dict(system.simulator.incident), MockProvider(), system.gateway)
    assert result.recommended_action is not None and result.recommended_action.tool_name == "revoke_sessions"
    assert result.action_result is not None and result.action_result.status is ExecutionStatus.EXECUTED
    assert system.simulator.revoked_sessions == {"u-alex-rivera": 1}
    assert len(system.executor.receipts) == 1


@opa_available
@pytest.mark.policy
async def test_recommend_only_level_denies_every_state_change() -> None:
    system = System(OpaExecPolicyEngine(), level=AuthorityLevel.L3_RECOMMEND)
    result = await run_investigation(INC, dict(system.simulator.incident), MockProvider(), system.gateway)
    assert result.action_result is not None and result.action_result.status is ExecutionStatus.DENIED
    assert "authority_below_action_threshold" in result.action_result.reason_codes
    assert system.simulator.snapshot()["execution_log"] == []
