from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import Depends, HTTPException, Request

from soclab.api.state import AppState


def get_state(request: Request) -> AppState:
    state: AppState = request.app.state.lab
    return state


def parse_id(value: str) -> UUID:
    try:
        return UUID(value)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="invalid id") from exc


State = Annotated[AppState, Depends(get_state)]
