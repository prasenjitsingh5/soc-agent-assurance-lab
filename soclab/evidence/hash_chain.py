"""Canonical hashing and chain verification. Pure functions, no I/O."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from datetime import datetime
from typing import Any
from uuid import UUID

from soclab.evidence.models import ChainVerification, StoredAuditEvent

GENESIS_HASH = "0" * 64


def canonical_json(value: Any) -> str:
    """Deterministic JSON: sorted keys, no whitespace, non-ASCII preserved, no NaN."""
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False, default=str
    )


def payload_hash(payload: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def compute_event_hash(
    *,
    event_id: UUID,
    run_id: UUID,
    sequence: int,
    event_type: str,
    payload_hash_hex: str,
    previous_hash: str,
    recorded_at: datetime,
) -> str:
    header = {
        "event_id": str(event_id),
        "run_id": str(run_id),
        "sequence": sequence,
        "event_type": event_type,
        "payload_hash": payload_hash_hex,
        "previous_hash": previous_hash,
        "recorded_at": recorded_at.isoformat(),
    }
    return hashlib.sha256(canonical_json(header).encode("utf-8")).hexdigest()


def verify_events(run_id: UUID, events: Sequence[StoredAuditEvent]) -> ChainVerification:
    """Recompute the chain in stored order and report the first divergence."""
    previous = GENESIS_HASH
    for index, event in enumerate(events, start=1):
        if event.sequence != index:
            return ChainVerification(
                run_id=run_id,
                valid=False,
                length=len(events),
                first_invalid_sequence=index,
                reason=f"expected sequence {index}, found {event.sequence}",
            )
        if event.run_id != run_id:
            return ChainVerification(
                run_id=run_id,
                valid=False,
                length=len(events),
                first_invalid_sequence=index,
                reason="foreign run id",
            )
        if event.previous_hash != previous:
            return ChainVerification(
                run_id=run_id,
                valid=False,
                length=len(events),
                first_invalid_sequence=index,
                reason="broken link",
            )
        if payload_hash(event.payload) != event.payload_hash:
            return ChainVerification(
                run_id=run_id,
                valid=False,
                length=len(events),
                first_invalid_sequence=index,
                reason="payload modified",
            )
        expected = compute_event_hash(
            event_id=event.event_id,
            run_id=event.run_id,
            sequence=event.sequence,
            event_type=event.event_type,
            payload_hash_hex=event.payload_hash,
            previous_hash=event.previous_hash,
            recorded_at=event.recorded_at,
        )
        if expected != event.event_hash:
            return ChainVerification(
                run_id=run_id,
                valid=False,
                length=len(events),
                first_invalid_sequence=index,
                reason="header modified",
            )
        previous = event.event_hash
    return ChainVerification(
        run_id=run_id, valid=True, length=len(events), root_hash=previous if events else None
    )
