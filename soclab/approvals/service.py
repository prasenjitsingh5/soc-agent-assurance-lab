"""In-memory approval queue. Persistence arrives with the evidence store."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from pydantic import Field

from soclab.contracts import ActionProposal, ApprovalDecision, ApprovalRecord, StrictModel


class PendingApproval(StrictModel):
    approval_id: UUID = Field(default_factory=uuid4)
    proposal: ActionProposal
    requested_at: datetime
    reason_codes: tuple[str, ...]


class ApprovalService:
    """Creates pending requests and records human decisions.

    A decision binds to exactly one proposal id. Approvals expire after
    ``ttl_seconds`` and cannot be reused once consumed by an execution.
    """

    def __init__(self, *, ttl_seconds: int = 600) -> None:
        self._ttl = ttl_seconds
        self.pending: dict[UUID, PendingApproval] = {}
        self.records: dict[UUID, ApprovalRecord] = {}
        self.consumed: set[UUID] = set()

    def request(
        self, proposal: ActionProposal, reason_codes: tuple[str, ...], *, now: datetime | None = None
    ) -> PendingApproval:
        for existing in self.pending.values():
            if existing.proposal.proposal_id == proposal.proposal_id:
                return existing
        pending = PendingApproval(
            proposal=proposal, requested_at=now or datetime.now(tz=UTC), reason_codes=reason_codes
        )
        self.pending[pending.approval_id] = pending
        return pending

    def decide(
        self,
        approval_id: UUID,
        approver_id: str,
        decision: ApprovalDecision,
        reason: str,
        *,
        now: datetime | None = None,
    ) -> ApprovalRecord:
        pending = self.pending.pop(approval_id, None)
        if pending is None:
            msg = f"no pending approval {approval_id}"
            raise KeyError(msg)
        if approver_id == pending.proposal.delegated_user_id or approver_id == pending.proposal.agent_id:
            msg = "the requesting identity cannot approve its own action"
            raise PermissionError(msg)
        moment = now or datetime.now(tz=UTC)
        record = ApprovalRecord(
            approval_id=approval_id,
            proposal_id=pending.proposal.proposal_id,
            approver_id=approver_id,
            decision=decision,
            reason=reason,
            decided_at=moment,
            expires_at=moment + timedelta(seconds=self._ttl),
        )
        self.records[approval_id] = record
        return record

    def valid_for(self, proposal: ActionProposal, *, now: datetime | None = None) -> ApprovalRecord | None:
        """Return the unexpired, unconsumed approval for this proposal, or None."""
        moment = now or datetime.now(tz=UTC)
        for record in self.records.values():
            if (
                record.proposal_id == proposal.proposal_id
                and record.approval_id not in self.consumed
                and record.is_valid_at(moment)
            ):
                return record
        return None

    def consume(self, approval_id: UUID) -> None:
        self.consumed.add(approval_id)
