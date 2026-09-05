"""Executive and technical reports for a stored campaign.

HTML and JSON come straight from the generator. The PDF is the one-page
executive summary built from the same JSON scorecard; it needs the optional
``pdf`` extra and answers 501 with the install line when that is missing.
"""

from __future__ import annotations

import json
from uuid import UUID

from fastapi import APIRouter, HTTPException, Response
from fastapi.responses import HTMLResponse, JSONResponse

from soclab.api.routes._deps import State
from soclab.api.state import AppState
from soclab.reports import (
    GeneratedReport,
    PdfSupportMissingError,
    ReportAudience,
    ReportGenerator,
    render_pdf,
    report_timestamp,
    summary_from_report,
)

router = APIRouter(tags=["reports"])


def _generate(
    state: AppState, campaign_id: UUID, audience: ReportAudience, baseline: UUID | None
) -> GeneratedReport:
    record = state.campaigns.get(campaign_id)
    if record is None:
        raise HTTPException(status_code=404, detail="unknown campaign")
    base = state.campaigns.get(baseline) if baseline else None
    return ReportGenerator(state.repository).generate(
        record.result,
        record.assurance,
        audience,
        baseline=base.assurance if base else None,
        comparison=[base.assurance, record.assurance] if base else None,
    )


@router.get("/campaigns/{campaign_id}/reports/{audience}", response_class=HTMLResponse)
def report_html(
    campaign_id: UUID, audience: ReportAudience, state: State, baseline: UUID | None = None
) -> HTMLResponse:
    return HTMLResponse(_generate(state, campaign_id, audience, baseline).html)


@router.get("/campaigns/{campaign_id}/reports/{audience}/json")
def report_json(
    campaign_id: UUID, audience: ReportAudience, state: State, baseline: UUID | None = None
) -> JSONResponse:
    return JSONResponse(content=json.loads(_generate(state, campaign_id, audience, baseline).json_payload))


@router.get("/campaigns/{campaign_id}/reports/executive/pdf")
def report_pdf(campaign_id: UUID, state: State, baseline: UUID | None = None) -> Response:
    report = _generate(state, campaign_id, ReportAudience.EXECUTIVE, baseline)
    summary = summary_from_report(report, generated_at=report_timestamp())
    try:
        data = render_pdf(summary)
    except PdfSupportMissingError as exc:
        raise HTTPException(status_code=501, detail=str(exc)) from exc
    headers = {"Content-Disposition": f'inline; filename="executive-{campaign_id}.pdf"'}
    return Response(content=data, media_type="application/pdf", headers=headers)
