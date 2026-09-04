"""SQLAlchemy-backed append-only store. SQLite by default, PostgreSQL in Docker."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import (
    Column,
    DateTime,
    Integer,
    MetaData,
    String,
    Table,
    Text,
    UniqueConstraint,
    create_engine,
    select,
)
from sqlalchemy.engine import Engine

from soclab.evidence.hash_chain import GENESIS_HASH, compute_event_hash, payload_hash, verify_events
from soclab.evidence.models import AuditEvent, ChainVerification, StoredAuditEvent

metadata = MetaData()

audit_events = Table(
    "audit_events",
    metadata,
    Column("event_id", String(36), primary_key=True),
    Column("run_id", String(36), nullable=False, index=True),
    Column("sequence", Integer, nullable=False),
    Column("event_type", String(120), nullable=False),
    Column("payload", Text, nullable=False),
    Column("payload_hash", String(64), nullable=False),
    Column("previous_hash", String(64), nullable=False),
    Column("event_hash", String(64), nullable=False),
    Column("recorded_at", DateTime(timezone=True), nullable=False),
    UniqueConstraint("run_id", "sequence", name="uq_run_sequence"),
)


class EvidenceRepository:
    """Append events, read them back in order, verify the chain.

    Methods prefixed ``unsafe_`` exist only so tests can prove that tampering
    is detected. They bypass hashing on purpose and must never be exposed
    through the API.
    """

    def __init__(self, url: str = "sqlite+pysqlite:///:memory:", *, engine: Engine | None = None) -> None:
        self._engine = engine or create_engine(url, future=True)
        metadata.create_all(self._engine)

    # ------------------------------------------------------------ writes
    def append_event(self, event: AuditEvent, *, recorded_at: datetime | None = None) -> StoredAuditEvent:
        moment = recorded_at or datetime.now(tz=UTC)
        with self._engine.begin() as conn:
            last = conn.execute(
                select(audit_events.c.sequence, audit_events.c.event_hash)
                .where(audit_events.c.run_id == str(event.run_id))
                .order_by(audit_events.c.sequence.desc())
                .limit(1)
            ).first()
            sequence = 1 if last is None else int(last.sequence) + 1
            previous = GENESIS_HASH if last is None else str(last.event_hash)
            p_hash = payload_hash(event.payload)
            e_hash = compute_event_hash(
                event_id=event.event_id,
                run_id=event.run_id,
                sequence=sequence,
                event_type=event.event_type,
                payload_hash_hex=p_hash,
                previous_hash=previous,
                recorded_at=moment,
            )
            conn.execute(
                audit_events.insert().values(
                    event_id=str(event.event_id),
                    run_id=str(event.run_id),
                    sequence=sequence,
                    event_type=event.event_type,
                    payload=json.dumps(event.payload, sort_keys=True, default=str),
                    payload_hash=p_hash,
                    previous_hash=previous,
                    event_hash=e_hash,
                    recorded_at=moment,
                )
            )
        return StoredAuditEvent(
            event_id=event.event_id,
            run_id=event.run_id,
            sequence=sequence,
            event_type=event.event_type,
            payload=event.payload,
            payload_hash=p_hash,
            previous_hash=previous,
            event_hash=e_hash,
            recorded_at=moment,
        )

    # ------------------------------------------------------------ reads
    def events_for(self, run_id: UUID) -> list[StoredAuditEvent]:
        with self._engine.connect() as conn:
            rows = conn.execute(
                select(audit_events)
                .where(audit_events.c.run_id == str(run_id))
                .order_by(audit_events.c.sequence)
            ).all()
        out: list[StoredAuditEvent] = []
        for row in rows:
            recorded = row.recorded_at if row.recorded_at.tzinfo else row.recorded_at.replace(tzinfo=UTC)
            out.append(
                StoredAuditEvent(
                    event_id=UUID(row.event_id),
                    run_id=UUID(row.run_id),
                    sequence=row.sequence,
                    event_type=row.event_type,
                    payload=json.loads(row.payload),
                    payload_hash=row.payload_hash,
                    previous_hash=row.previous_hash,
                    event_hash=row.event_hash,
                    recorded_at=recorded,
                )
            )
        return out

    def run_ids(self) -> list[UUID]:
        with self._engine.connect() as conn:
            rows = conn.execute(select(audit_events.c.run_id).distinct()).all()
        return [UUID(r.run_id) for r in rows]

    def verify_chain(self, run_id: UUID) -> ChainVerification:
        return verify_events(run_id, self.events_for(run_id))

    def root_hash(self, run_id: UUID) -> str | None:
        return self.verify_chain(run_id).root_hash

    # ------------------------------------------------------------ test-only tampering
    def unsafe_modify_for_test(self, run_id: UUID, sequence: int, field: str, value: Any) -> None:
        with self._engine.begin() as conn:
            row = conn.execute(
                select(audit_events).where(
                    audit_events.c.run_id == str(run_id), audit_events.c.sequence == sequence
                )
            ).one()
            payload = json.loads(row.payload)
            payload[field] = value
            conn.execute(
                audit_events.update()
                .where(audit_events.c.event_id == row.event_id)
                .values(payload=json.dumps(payload, sort_keys=True, default=str))
            )

    def unsafe_delete_for_test(self, run_id: UUID, sequence: int) -> None:
        with self._engine.begin() as conn:
            conn.execute(
                audit_events.delete().where(
                    audit_events.c.run_id == str(run_id), audit_events.c.sequence == sequence
                )
            )

    def unsafe_swap_for_test(self, run_id: UUID, a: int, b: int) -> None:
        with self._engine.begin() as conn:
            rows = {
                r.sequence: r.event_id
                for r in conn.execute(
                    select(audit_events.c.sequence, audit_events.c.event_id).where(
                        audit_events.c.run_id == str(run_id), audit_events.c.sequence.in_([a, b])
                    )
                ).all()
            }
            conn.execute(audit_events.update().where(audit_events.c.event_id == rows[a]).values(sequence=-1))
            conn.execute(audit_events.update().where(audit_events.c.event_id == rows[b]).values(sequence=a))
            conn.execute(audit_events.update().where(audit_events.c.event_id == rows[a]).values(sequence=b))

    def unsafe_insert_for_test(
        self, run_id: UUID, sequence: int, event_type: str, payload: dict[str, Any]
    ) -> None:
        """Insert a well-formed looking record at a sequence position, shifting later ones up."""
        with self._engine.begin() as conn:
            later = conn.execute(
                select(audit_events.c.event_id, audit_events.c.sequence)
                .where(audit_events.c.run_id == str(run_id), audit_events.c.sequence >= sequence)
                .order_by(audit_events.c.sequence.desc())
            ).all()
            for row in later:
                conn.execute(
                    audit_events.update()
                    .where(audit_events.c.event_id == row.event_id)
                    .values(sequence=row.sequence + 1)
                )
            from uuid import uuid4

            p_hash = payload_hash(payload)
            conn.execute(
                audit_events.insert().values(
                    event_id=str(uuid4()),
                    run_id=str(run_id),
                    sequence=sequence,
                    event_type=event_type,
                    payload=json.dumps(payload, sort_keys=True),
                    payload_hash=p_hash,
                    previous_hash=GENESIS_HASH,
                    event_hash=p_hash,
                    recorded_at=datetime.now(tz=UTC),
                )
            )
