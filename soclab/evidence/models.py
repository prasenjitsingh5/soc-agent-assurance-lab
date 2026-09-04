"""Audit event contracts."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from pydantic import Field

from soclab.contracts import StrictModel


class AuditEvent(StrictModel):
    """What a component asks to record. Sequence and hashes are assigned by the repository."""

    event_id: UUID = Field(default_factory=uuid4)
    run_id: UUID
    event_type: str = Field(pattern=r"^[a-z][a-z0-9_.]*$")
    payload: dict[str, Any]


class StoredAuditEvent(StrictModel):
    event_id: UUID
    run_id: UUID
    sequence: int = Field(ge=1)
    event_type: str
    payload: dict[str, Any]
    payload_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    previous_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    event_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    recorded_at: datetime


class ChainVerification(StrictModel):
    run_id: UUID
    valid: bool
    length: int = Field(ge=0)
    root_hash: str | None = None
    first_invalid_sequence: int | None = None
    reason: str | None = None
