"""Domain contracts. All models are strict, immutable and JSON round-trippable."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from soclab.contracts.enums import ApprovalDecision, DecisionOutcome, RiskTier, TrustLabel


def utc_now() -> datetime:
    return datetime.now(tz=UTC)


class StrictModel(BaseModel):
    """Base for every contract: unknown fields rejected, values frozen after creation."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


def _require_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        msg = "timestamps must be timezone-aware UTC"
        raise ValueError(msg)
    return value.astimezone(UTC)


class EvidenceRef(StrictModel):
    """A pointer to one piece of evidence with its provenance."""

    evidence_id: str = Field(min_length=1)
    source_tool: str = Field(min_length=1)
    incident_id: str = Field(min_length=1)
    trust: TrustLabel
    content_hash: str = Field(min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$")
    summary: str = Field(min_length=1, max_length=500)


class ActionProposal(StrictModel):
    """What a model wants done. It is untrusted until the policy engine says otherwise."""

    proposal_id: UUID = Field(default_factory=uuid4)
    agent_id: str = Field(min_length=1)
    delegated_user_id: str = Field(min_length=1)
    incident_id: str = Field(min_length=1)
    tool_name: str = Field(min_length=1, pattern=r"^[a-z][a-z0-9_]*$")
    arguments: dict[str, Any]
    evidence_refs: tuple[EvidenceRef, ...] = Field(min_length=1)
    rationale: str = Field(min_length=1, max_length=2000)
    provider: str = Field(min_length=1)
    model: str = Field(min_length=1)
    trace_id: str = Field(min_length=1)
    created_at: datetime = Field(default_factory=utc_now)

    _utc = field_validator("created_at")(_require_utc)

    @field_validator("evidence_refs")
    @classmethod
    def _evidence_matches_incident(cls, refs: tuple[EvidenceRef, ...], info: Any) -> tuple[EvidenceRef, ...]:
        incident = info.data.get("incident_id")
        if incident is not None and any(r.incident_id != incident for r in refs):
            msg = "evidence must belong to the proposal's incident"
            raise ValueError(msg)
        return refs


class Obligation(StrictModel):
    """Something the gateway must do before the tool runs, e.g. redact a field."""

    name: str = Field(min_length=1, pattern=r"^[a-z][a-z0-9_]*$")
    parameters: dict[str, Any] = Field(default_factory=dict)


class PolicyDecision(StrictModel):
    """Result of evaluating one proposal against the versioned policy."""

    proposal_id: UUID
    outcome: DecisionOutcome
    reason_codes: tuple[str, ...] = Field(min_length=1)
    obligations: tuple[Obligation, ...] = ()
    risk_tier: RiskTier
    policy_version: str = Field(min_length=1)
    explanation: str = Field(min_length=1, max_length=2000)
    decided_at: datetime = Field(default_factory=utc_now)

    _utc = field_validator("decided_at")(_require_utc)

    @model_validator(mode="after")
    def _obligations_only_when_declared(self) -> PolicyDecision:
        if self.outcome == DecisionOutcome.ALLOW_WITH_OBLIGATIONS and not self.obligations:
            msg = "allow_with_obligations requires at least one obligation"
            raise ValueError(msg)
        if self.outcome in {DecisionOutcome.ALLOW, DecisionOutcome.DENY} and self.obligations:
            msg = f"{self.outcome} cannot carry obligations"
            raise ValueError(msg)
        return self


class ApprovalRecord(StrictModel):
    """A human decision on a proposal that required approval."""

    approval_id: UUID = Field(default_factory=uuid4)
    proposal_id: UUID
    approver_id: str = Field(min_length=1)
    decision: ApprovalDecision
    reason: str = Field(min_length=1, max_length=2000)
    decided_at: datetime = Field(default_factory=utc_now)
    expires_at: datetime

    _utc_decided = field_validator("decided_at")(_require_utc)
    _utc_expires = field_validator("expires_at")(_require_utc)

    @field_validator("expires_at")
    @classmethod
    def _expiry_after_decision(cls, expires_at: datetime, info: Any) -> datetime:
        decided = info.data.get("decided_at")
        if decided is not None and expires_at <= decided:
            msg = "expires_at must be after decided_at"
            raise ValueError(msg)
        return expires_at

    def is_valid_at(self, moment: datetime) -> bool:
        return self.decision == ApprovalDecision.APPROVED and moment < self.expires_at


class ProviderCapabilities(StrictModel):
    """What an adapter declares it can do. Absent capabilities are explicit, never assumed."""

    tool_calling: bool
    structured_output: bool
    streaming: bool
    usage_reporting: bool
    multimodal_input: bool = False


class CompatibilityResult(StrictModel):
    """Registry answer for one provider: can we use it, and with which caveats."""

    provider_id: str = Field(min_length=1)
    adapter_version: str = Field(min_length=1)
    approved: bool
    capabilities: ProviderCapabilities
    region: str | None = None
    limitations: tuple[str, ...] = ()
