"""Run campaigns and read their assurance results."""

from __future__ import annotations

from typing import Any
from uuid import UUID

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from soclab.api.routes._deps import State
from soclab.api.state import CampaignRecord
from soclab.contracts import AuthorityLevel
from soclab.evaluator import CampaignConfig, load_attack_scenarios, run_campaign
from soclab.policy import (
    ManagedOpaServer,
    OpaHttpPolicyEngine,
    PolicyEngine,
    PolicyUnavailableError,
    find_opa_binary,
)
from soclab.providers.base import ProviderError
from soclab.providers.registry import ProviderRegistry
from soclab.reports import comparison_table
from soclab.scoring import score_campaign

router = APIRouter(tags=["campaigns"])


class CampaignRequest(BaseModel):
    mode: str = Field(pattern=r"^(baseline|protected)$")
    authority_level: AuthorityLevel = AuthorityLevel.L4_ACT_WITH_APPROVAL
    scenario_ids: list[str] | None = None
    repeats: int = Field(default=1, ge=1, le=10)
    provider_id: str = Field(default="mock", pattern=r"^[a-z][a-z0-9_]*$")
    model: str | None = Field(default=None, min_length=1, max_length=200)


def _resolve_model(provider_id: str, model: str | None) -> str:
    """Check the provider id against the registry before any run starts. Unknown or unconfigured is a 400."""
    registry = ProviderRegistry()
    try:
        entry = registry.entry(provider_id)
    except ProviderError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if not registry.configured(provider_id):
        detail = f"provider {provider_id!r} is not configured; set {', '.join(entry.required_env)}"
        raise HTTPException(status_code=400, detail=detail)
    return model or entry.default_model


def _engine(state_url: str | None) -> tuple[PolicyEngine, ManagedOpaServer | None]:
    import os

    url = state_url or os.environ.get("SOCLAB_OPA_URL")
    if url:
        return OpaHttpPolicyEngine(url), None
    if find_opa_binary() is None:
        raise HTTPException(
            status_code=503, detail="policy decision point unavailable; protected mode refused"
        )
    server = ManagedOpaServer()
    return server.start(), server


@router.get("/scenarios")
def list_scenarios() -> list[dict[str, Any]]:
    return [s.model_dump(mode="json") for s in load_attack_scenarios()]


@router.post("/campaigns", status_code=201)
async def create_campaign(body: CampaignRequest, state: State) -> dict[str, Any]:
    model = _resolve_model(body.provider_id, body.model)
    config = CampaignConfig(
        mode=body.mode,
        authority_level=body.authority_level,
        scenario_ids=tuple(body.scenario_ids) if body.scenario_ids else None,
        repeats=body.repeats,
        provider_id=body.provider_id,
        model=model,
        approved_models=((body.provider_id, model),),
    )
    server: ManagedOpaServer | None = None
    engine: PolicyEngine | None = None
    try:
        if body.mode == "protected":
            try:
                engine, server = _engine(None)
            except PolicyUnavailableError as exc:
                raise HTTPException(status_code=503, detail=str(exc)) from exc
        result = await run_campaign(config, policy=engine, repository=state.repository)
    finally:
        if server is not None:
            server.stop()
    assurance = score_campaign(result)
    state.campaigns[result.campaign_id] = CampaignRecord(result=result, assurance=assurance)
    return {"campaign_id": str(result.campaign_id), "assurance": assurance.model_dump(mode="json")}


@router.get("/campaigns")
def list_campaigns(state: State) -> list[dict[str, Any]]:
    return comparison_table([rec.assurance for rec in state.campaigns.values()])


@router.get("/campaigns/{campaign_id}")
def get_campaign(campaign_id: UUID, state: State) -> dict[str, Any]:
    record = state.campaigns.get(campaign_id)
    if record is None:
        raise HTTPException(status_code=404, detail="unknown campaign")
    return {
        "campaign_id": str(campaign_id),
        "assurance": record.assurance.model_dump(mode="json"),
        "outcomes": [o.model_dump(mode="json") for o in record.result.outcomes],
    }
