"""Evidence chain access. Read-only; tampering helpers are never exposed."""

from __future__ import annotations

from typing import Any
from uuid import UUID

from fastapi import APIRouter

from soclab.api.routes._deps import State

router = APIRouter(tags=["evidence"])


@router.get("/runs")
def list_runs(state: State) -> list[dict[str, Any]]:
    rows = []
    for run_id in state.repository.run_ids():
        verification = state.repository.verify_chain(run_id)
        rows.append({"run_id": str(run_id), "length": verification.length, "valid": verification.valid})
    return rows


@router.get("/runs/{run_id}/events")
def run_events(run_id: UUID, state: State) -> list[dict[str, Any]]:
    return [e.model_dump(mode="json") for e in state.repository.events_for(run_id)]


@router.get("/runs/{run_id}/verify")
def verify(run_id: UUID, state: State) -> dict[str, Any]:
    return state.repository.verify_chain(run_id).model_dump(mode="json")
