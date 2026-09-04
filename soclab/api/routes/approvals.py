"""Human approval queue. Decisions are attributable and expire."""

from __future__ import annotations

from typing import Any
from uuid import UUID

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from soclab.api.routes._deps import State
from soclab.contracts import ApprovalDecision

router = APIRouter(tags=["approvals"])


class DecisionRequest(BaseModel):
    approver_id: str = Field(min_length=1)
    decision: ApprovalDecision
    reason: str = Field(min_length=1, max_length=2000)


@router.get("/approvals")
def list_pending(state: State) -> list[dict[str, Any]]:
    return [
        {
            "approval_id": str(p.approval_id),
            "proposal_id": str(p.proposal.proposal_id),
            "tool_name": p.proposal.tool_name,
            "arguments": p.proposal.arguments,
            "incident_id": p.proposal.incident_id,
            "requested_at": p.requested_at.isoformat(),
            "reason_codes": list(p.reason_codes),
        }
        for p in state.approvals.pending.values()
    ]


@router.post("/approvals/{approval_id}/decision")
def decide(approval_id: UUID, body: DecisionRequest, state: State) -> dict[str, Any]:
    try:
        record = state.approvals.decide(approval_id, body.approver_id, body.decision, body.reason)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="no such pending approval") from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    return record.model_dump(mode="json")


@router.get("/approvals/history")
def history(state: State) -> list[dict[str, Any]]:
    return [r.model_dump(mode="json") for r in state.approvals.records.values()]
