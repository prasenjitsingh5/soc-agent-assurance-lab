"""The orchestrator's only path to a tool."""

from __future__ import annotations

from typing import Any, Protocol

from pydantic import Field

from soclab.contracts import ActionProposal, DecisionOutcome, ExecutionStatus, StrictModel
from soclab.simulator import STATE_CHANGING_TOOLS, SimulatorState, ToolError, execute_tool


class ProposalResult(StrictModel):
    """What came back from submitting a proposal. Read-only results carry the tool output."""

    proposal_id: str
    status: ExecutionStatus
    outcome: DecisionOutcome | None = None
    reason_codes: tuple[str, ...] = ()
    output: dict[str, Any] | None = None
    receipt: dict[str, Any] | None = None
    error: str | None = None
    controlled: bool = Field(description="True when a policy decision point evaluated the proposal")


class ToolProposalPort(Protocol):
    async def propose(self, proposal: ActionProposal) -> ProposalResult: ...


class BaselinePort:
    """Weak-control baseline: whatever the model proposes runs against the simulator.

    This is the configuration the lab exists to measure against. It performs no
    policy evaluation, no scope check beyond the simulator's own and no approval.
    ``allow_state_changes=False`` turns it into a recommend-only port for L3 runs.
    """

    def __init__(self, simulator: SimulatorState, *, allow_state_changes: bool = True) -> None:
        self._simulator = simulator
        self._allow_state_changes = allow_state_changes
        self.proposals: list[ActionProposal] = []

    async def propose(self, proposal: ActionProposal) -> ProposalResult:
        self.proposals.append(proposal)
        pid = str(proposal.proposal_id)
        state_changing = proposal.tool_name in STATE_CHANGING_TOOLS
        if state_changing and not self._allow_state_changes:
            return ProposalResult(
                proposal_id=pid,
                status=ExecutionStatus.PROPOSED,
                reason_codes=("recommend_only_mode",),
                controlled=False,
            )
        try:
            result = await execute_tool(
                self._simulator,
                proposal.tool_name,
                {"incident_id": proposal.incident_id, **proposal.arguments},
            )
        except (ToolError, PermissionError, TypeError) as exc:
            return ProposalResult(
                proposal_id=pid,
                status=ExecutionStatus.FAILED_CLOSED if state_changing else ExecutionStatus.DENIED,
                reason_codes=(type(exc).__name__,),
                error=str(exc),
                controlled=False,
            )
        if state_changing:
            return ProposalResult(
                proposal_id=pid, status=ExecutionStatus.EXECUTED, receipt=result, controlled=False
            )
        return ProposalResult(
            proposal_id=pid, status=ExecutionStatus.EXECUTED, output=result, controlled=False
        )
