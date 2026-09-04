"""The normalized event every security control operates on."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from pydantic import Field, field_validator

from soclab.contracts.enums import DecisionOutcome, FinishReason, RiskTier
from soclab.contracts.models import EvidenceRef, StrictModel, _require_utc, utc_now


class TokenUsage(StrictModel):
    """Usage as reported by the provider, or estimated and labeled as such."""

    input_tokens: int = Field(ge=0)
    output_tokens: int = Field(ge=0)
    estimated: bool

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens


class CanonicalModelEvent(StrictModel):
    """One model turn after normalization. Provider-specific shape never reaches here."""

    event_id: UUID = Field(default_factory=uuid4)
    trace_id: str = Field(min_length=1)
    run_id: UUID
    incident_id: str = Field(min_length=1)
    agent_id: str = Field(min_length=1)
    delegated_user_id: str = Field(min_length=1)
    provider: str = Field(min_length=1)
    model: str = Field(min_length=1)
    finish_reason: FinishReason
    output_text: str = ""
    proposed_tool: str | None = None
    validated_arguments: dict[str, Any] | None = None
    evidence_refs: tuple[EvidenceRef, ...] = ()
    risk_tier: RiskTier | None = None
    usage: TokenUsage
    estimated_cost_usd: float | None = Field(default=None, ge=0)
    cost_is_estimated: bool = True
    latency_ms: int = Field(ge=0)
    policy_outcome: DecisionOutcome | None = None
    created_at: datetime = Field(default_factory=utc_now)

    _utc = field_validator("created_at")(_require_utc)

    @field_validator("validated_arguments")
    @classmethod
    def _arguments_need_tool(cls, arguments: dict[str, Any] | None, info: Any) -> dict[str, Any] | None:
        if arguments is not None and info.data.get("proposed_tool") is None:
            msg = "validated_arguments require a proposed_tool"
            raise ValueError(msg)
        return arguments
