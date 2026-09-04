"""Hash-chained evidence store.

Every consequential event in a run is appended to a chain where each record's
hash covers its own content and the previous record's hash. Verification
recomputes the chain from the first record and reports the first sequence
number at which the stored data no longer matches. This gives tamper
evidence. It does not make the underlying database immutable; the production
reference exports the chain to write-once storage for that.
"""

from soclab.evidence.hash_chain import (
    GENESIS_HASH,
    canonical_json,
    compute_event_hash,
    payload_hash,
    verify_events,
)
from soclab.evidence.models import AuditEvent, ChainVerification, StoredAuditEvent
from soclab.evidence.repository import EvidenceRepository

__all__ = [
    "GENESIS_HASH",
    "AuditEvent",
    "ChainVerification",
    "EvidenceRepository",
    "StoredAuditEvent",
    "canonical_json",
    "compute_event_hash",
    "payload_hash",
    "verify_events",
]
