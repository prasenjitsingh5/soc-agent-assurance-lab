"""FastAPI composition root.

The API exposes the same evidence the CLI writes: incidents, campaigns,
approvals, evidence chains and reports under ``/api/v1``. It never bypasses
the control gateway; approvals recorded here feed the same
:class:`ApprovalService` the gateway consults.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from uuid import UUID

from fastapi import FastAPI, HTTPException

from soclab import __version__
from soclab.api.routes import approvals, campaigns, evidence, incidents, reports
from soclab.api.state import AppState
from soclab.evidence import EvidenceRepository

DEFAULT_DB = "sqlite+pysqlite:///./runs/soclab.sqlite"


def build_state() -> AppState:
    url = os.environ.get("SOCLAB_DATABASE_URL", DEFAULT_DB)
    return AppState(repository=EvidenceRepository(url))


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    if not hasattr(app.state, "lab"):
        app.state.lab = build_state()
    yield


def create_app(state: AppState | None = None) -> FastAPI:
    app = FastAPI(title="SOC Agent Assurance Lab", version=__version__, lifespan=_lifespan)
    if state is not None:
        app.state.lab = state

    @app.get("/health")
    def health() -> dict[str, str]:
        """Liveness probe used by the container health check and the smoke test."""
        return {"status": "ok"}

    @app.get("/api/v1/version")
    def version() -> dict[str, str]:
        return {"version": __version__}

    app.include_router(incidents.router, prefix="/api/v1")
    app.include_router(campaigns.router, prefix="/api/v1")
    app.include_router(approvals.router, prefix="/api/v1")
    app.include_router(evidence.router, prefix="/api/v1")
    app.include_router(reports.router, prefix="/api/v1")
    return app


app = create_app()


def parse_uuid(value: str) -> UUID:
    try:
        return UUID(value)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="invalid id") from exc


__all__ = ["app", "create_app", "parse_uuid"]
