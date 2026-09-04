"""Synthetic incidents and the fixture behind them."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException

from soclab.evaluator import load_incident
from soclab.simulator import SimulatorState

router = APIRouter(tags=["incidents"])


@router.get("/incidents")
def list_incidents() -> list[dict[str, Any]]:
    incident = load_incident()
    return [incident.model_dump(mode="json")]


@router.get("/incidents/{incident_id}")
def get_incident(incident_id: str) -> dict[str, Any]:
    incident = load_incident()
    if incident.id != incident_id:
        raise HTTPException(status_code=404, detail="unknown incident")
    simulator = SimulatorState.from_fixture(incident.fixture)
    return {
        **incident.model_dump(mode="json"),
        "fixture_version": simulator.fixture_version,
        "users": list(simulator.users),
        "endpoints": list(simulator.endpoints),
        "siem_event_count": len(simulator.siem_events),
        "injected_event_ids": [e["event_id"] for e in simulator.siem_events if e.get("injected")],
    }
