"""Control gateway.

Every proposal from the orchestrator passes through :meth:`ControlGateway.propose`.
The gateway:

1. validates the proposal against the tool registry and run limits;
2. builds the authorization context (never from model output);
3. asks the policy decision point;
4. fulfils obligations deterministically;
5. resolves approvals for escalated actions;
6. issues a signed grant and hands proposal plus grant to the executor;
7. records a :class:`GatewayEvent` for every step, allowed or not.

Any policy outage fails closed for state-changing tools. Read-only tools may
continue only when ``degraded_read_only`` is enabled in the configuration, and
that continuation is itself recorded as a degradation event.
"""

from __future__ import annotations

import json
import time
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from pydantic import Field

from soclab.approvals import ApprovalService
from soclab.contracts import (
    ActionProposal,
    AuthorityLevel,
    DecisionOutcome,
    ExecutionStatus,
    Obligation,
    PolicyDecision,
    RiskTier,
    StrictModel,
)
from soclab.executor import AuthorizationError, Executor
from soclab.grants import ExecutionGrant, GrantSigner
from soclab.orchestrator.ports import ProposalResult
from soclab.policy import (
    ApprovalContext,
    AuthorizationContext,
    LimitContext,
    PolicyEngine,
    PolicyUnavailableError,
    ProtectedAssets,
    ToolRegistryEntry,
    default_tool_registry,
)
from soclab.redaction import redact_secrets


class RunLimits(StrictModel):
    max_calls: int = Field(default=40, gt=0)
    max_cost_usd: float = Field(default=2.0, gt=0)
    max_elapsed_seconds: float = Field(default=300.0, gt=0)


class GatewayConfig(StrictModel):
    incident_id: str
    authority_level: AuthorityLevel = AuthorityLevel.L4_ACT_WITH_APPROVAL
    approved_models: tuple[tuple[str, str], ...] = (("mock", "mock-investigator-v1"),)
    limits: RunLimits = RunLimits()
    degraded_read_only: bool = False
    canary_patterns: tuple[str, ...] = ("CANARY-SECRET-*",)
    protected_assets: ProtectedAssets = ProtectedAssets()


class GatewayEvent(StrictModel):
    """One line of the gateway's own audit trail. Feeds the evidence chain later."""

    event_id: UUID = Field(default_factory=uuid4)
    proposal_id: UUID
    kind: str
    at: datetime
    detail: dict[str, Any]


class ControlGateway:
    def __init__(
        self,
        *,
        config: GatewayConfig,
        policy: PolicyEngine,
        executor: Executor,
        signer: GrantSigner,
        approvals: ApprovalService,
        tools: dict[str, ToolRegistryEntry] | None = None,
        clock: Any = None,
    ) -> None:
        self._config = config
        self._policy = policy
        self._executor = executor
        self._signer = signer
        self._approvals = approvals
        self._tools = tools or default_tool_registry()
        self._clock = clock or (lambda: datetime.now(tz=UTC))
        self._started = time.monotonic()
        self.calls_made = 0
        self.cost_used_usd = 0.0
        self.events: list[GatewayEvent] = []
        self.decisions: dict[UUID, PolicyDecision] = {}
        self.grants: dict[UUID, ExecutionGrant] = {}

    # ------------------------------------------------------------ helpers
    def _now(self) -> datetime:
        now: datetime = self._clock()
        return now

    def _record(self, proposal_id: UUID, kind: str, **detail: Any) -> None:
        self.events.append(GatewayEvent(proposal_id=proposal_id, kind=kind, at=self._now(), detail=detail))

    def record_cost(self, usd: float) -> None:
        """Model spend reported by the orchestrator. Counts toward the cost limit the policy enforces."""
        self.cost_used_usd += max(0.0, usd)

    def _context(self, proposal: ActionProposal) -> AuthorizationContext:
        approval = self._approvals.valid_for(proposal, now=self._now())
        return AuthorizationContext(
            incident_id=self._config.incident_id,
            authority_level=self._config.authority_level,
            approved_models=self._config.approved_models,
            tools=self._tools,
            limits=LimitContext(
                calls_made=self.calls_made,
                max_calls=self._config.limits.max_calls,
                cost_used_usd=self.cost_used_usd,
                max_cost_usd=self._config.limits.max_cost_usd,
                elapsed_seconds=time.monotonic() - self._started,
                max_elapsed_seconds=self._config.limits.max_elapsed_seconds,
            ),
            approval=ApprovalContext(present=approval is not None, valid=approval is not None),
            protected_assets=self._config.protected_assets,
        )

    def _is_state_changing(self, proposal: ActionProposal) -> bool:
        entry = self._tools.get(proposal.tool_name)
        return entry is not None and entry.risk_tier is not RiskTier.READ_ONLY

    def _fulfil(self, obligations: tuple[Obligation, ...], proposal: ActionProposal) -> tuple[str, ...]:
        """Obligations that must happen before execution. Unknown obligations block execution."""
        done: list[str] = []
        for obligation in obligations:
            if obligation.name == "redact_secrets":
                done.append(obligation.name)  # applied to the output after the call, see propose()
            elif obligation.name == "record_reversal_plan":
                self._record(
                    proposal.proposal_id,
                    "reversal_plan",
                    tool=proposal.tool_name,
                    plan="simulated restore from receipt prior_state",
                )
                done.append(obligation.name)
            elif obligation.name == "notify_incident_owner":
                self._record(
                    proposal.proposal_id,
                    "notification",
                    channel=str(obligation.parameters.get("channel", "simulated")),
                )
                done.append(obligation.name)
            else:
                msg = f"unknown obligation {obligation.name!r}"
                raise PolicyUnavailableError(msg)
        return tuple(done)

    # ------------------------------------------------------------ port
    async def propose(self, proposal: ActionProposal) -> ProposalResult:
        pid = proposal.proposal_id
        state_changing = self._is_state_changing(proposal)
        self.calls_made += 1
        self._record(pid, "proposal_received", tool=proposal.tool_name, incident=proposal.incident_id)

        # 1. Policy decision. Outage fails closed for anything that changes state.
        try:
            decision = await self._policy.decide(proposal, self._context(proposal))
        except PolicyUnavailableError as exc:
            self._record(pid, "policy_unavailable", error=str(exc), state_changing=state_changing)
            if state_changing or not self._config.degraded_read_only:
                return ProposalResult(
                    proposal_id=str(pid),
                    status=ExecutionStatus.FAILED_CLOSED,
                    reason_codes=("policy_unavailable",),
                    error=str(exc),
                    controlled=True,
                )
            self._record(pid, "degraded_read_only_continuation")
            decision = PolicyDecision(
                proposal_id=pid,
                outcome=DecisionOutcome.ALLOW_WITH_OBLIGATIONS,
                reason_codes=("degraded_read_only",),
                obligations=(Obligation(name="redact_secrets"),),
                risk_tier=RiskTier.READ_ONLY,
                policy_version="degraded",
                explanation="policy unavailable; read-only continuation permitted by configuration",
            )
        self.decisions[pid] = decision
        self._record(
            pid,
            "policy_decision",
            outcome=decision.outcome.value,
            reasons=list(decision.reason_codes),
            version=decision.policy_version,
        )

        # 2. Deny and escalate paths.
        if decision.outcome is DecisionOutcome.DENY:
            return ProposalResult(
                proposal_id=str(pid),
                status=ExecutionStatus.DENIED,
                outcome=decision.outcome,
                reason_codes=decision.reason_codes,
                controlled=True,
            )
        if decision.outcome is DecisionOutcome.REQUIRE_APPROVAL:
            pending = self._approvals.request(proposal, decision.reason_codes, now=self._now())
            self._record(pid, "approval_requested", approval_id=str(pending.approval_id))
            return ProposalResult(
                proposal_id=str(pid),
                status=ExecutionStatus.AWAITING_APPROVAL,
                outcome=decision.outcome,
                reason_codes=decision.reason_codes,
                controlled=True,
            )

        # 3. Obligations, approval binding, grant.
        try:
            fulfilled = self._fulfil(decision.obligations, proposal)
        except PolicyUnavailableError as exc:
            self._record(pid, "obligation_failed", error=str(exc))
            return ProposalResult(
                proposal_id=str(pid),
                status=ExecutionStatus.FAILED_CLOSED,
                outcome=decision.outcome,
                reason_codes=("obligation_failed",),
                error=str(exc),
                controlled=True,
            )
        approval = self._approvals.valid_for(proposal, now=self._now()) if state_changing else None
        if (
            state_changing
            and self._config.authority_level is not AuthorityLevel.L5_BOUNDED_AUTONOMY
            and approval is None
            and decision.risk_tier is not RiskTier.LOW
        ):
            # Defense in depth: the policy said allow, but the gateway cannot find the approval it relied on.
            self._record(pid, "approval_binding_failed")
            return ProposalResult(
                proposal_id=str(pid),
                status=ExecutionStatus.FAILED_CLOSED,
                outcome=decision.outcome,
                reason_codes=("approval_not_bound",),
                controlled=True,
            )
        grant = self._signer.issue(
            proposal,
            policy_version=decision.policy_version,
            approval_id=approval.approval_id if approval else None,
            obligations_fulfilled=fulfilled,
            now=self._now(),
        )
        self.grants[grant.grant_id] = grant
        self._record(
            pid,
            "grant_issued",
            grant_id=str(grant.grant_id),
            approval_id=str(approval.approval_id) if approval else None,
        )

        # 4. Execute through the isolated executor.
        try:
            output = await self._executor.execute(proposal, grant, now=self._now())
        except AuthorizationError as exc:
            self._record(pid, "execution_refused", error=str(exc))
            return ProposalResult(
                proposal_id=str(pid),
                status=ExecutionStatus.FAILED_CLOSED,
                outcome=decision.outcome,
                reason_codes=("executor_refused",),
                error=str(exc),
                controlled=True,
            )
        if approval is not None:
            self._approvals.consume(approval.approval_id)
        if "redact_secrets" in fulfilled:
            output = redact_secrets(output, self._config.canary_patterns)
        self._record(pid, "executed", tool=proposal.tool_name, state_changing=state_changing)
        if state_changing:
            return ProposalResult(
                proposal_id=str(pid),
                status=ExecutionStatus.EXECUTED,
                outcome=decision.outcome,
                reason_codes=decision.reason_codes,
                receipt=output,
                controlled=True,
            )
        return ProposalResult(
            proposal_id=str(pid),
            status=ExecutionStatus.EXECUTED,
            outcome=decision.outcome,
            reason_codes=decision.reason_codes,
            output=output,
            controlled=True,
        )

    def audit_json(self) -> str:
        return json.dumps([e.model_dump(mode="json") for e in self.events], sort_keys=True)
