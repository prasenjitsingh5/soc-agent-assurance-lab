"""Executive and technical reports for a stored campaign."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse

from soclab.api.routes._deps import State
from soclab.reports import ReportAudience, ReportGenerator

router = APIRouter(tags=["reports"])


@router.get("/campaigns/{campaign_id}/reports/{audience}", response_class=HTMLResponse)
def report_html(
    campaign_id: UUID, audience: ReportAudience, state: State, baseline: UUID | None = None
) -> HTMLResponse:
    record = state.campaigns.get(campaign_id)
    if record is None:
        raise HTTPException(status_code=404, detail="unknown campaign")
    base = state.campaigns.get(baseline) if baseline else None
    comparison = [base.assurance, record.assurance] if base else None
    report = ReportGenerator(state.repository).generate(
        record.result,
        record.assurance,
        audience,
        baseline=base.assurance if base else None,
        comparison=comparison,
    )
    return HTMLResponse(report.html)


@router.get("/campaigns/{campaign_id}/reports/{audience}/json")
def report_json(campaign_id: UUID, audience: ReportAudience, state: State) -> JSONResponse:
    record = state.campaigns.get(campaign_id)
    if record is None:
        raise HTTPException(status_code=404, detail="unknown campaign")
    report = ReportGenerator(state.repository).generate(record.result, record.assurance, audience)
    return JSONResponse(content=__import__("json").loads(report.json_payload))
