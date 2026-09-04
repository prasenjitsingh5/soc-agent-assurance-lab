"""Canonical contracts shared by every component.

Provider payloads, policy responses and tool results are converted into these
models at the boundary. Nothing inside the lab reasons about a provider SDK
type or a raw OPA document.
"""

from soclab.contracts.enums import (
    ApprovalDecision,
    AuthorityLevel,
    DecisionOutcome,
    ExecutionStatus,
    FinishReason,
    RiskTier,
    TrustLabel,
)
from soclab.contracts.events import CanonicalModelEvent, TokenUsage
from soclab.contracts.models import (
    ActionProposal,
    ApprovalRecord,
    CompatibilityResult,
    EvidenceRef,
    Obligation,
    PolicyDecision,
    ProviderCapabilities,
    StrictModel,
)

__all__ = [
    "ActionProposal",
    "ApprovalDecision",
    "ApprovalRecord",
    "AuthorityLevel",
    "CanonicalModelEvent",
    "CompatibilityResult",
    "DecisionOutcome",
    "EvidenceRef",
    "ExecutionStatus",
    "FinishReason",
    "Obligation",
    "PolicyDecision",
    "ProviderCapabilities",
    "RiskTier",
    "StrictModel",
    "TokenUsage",
    "TrustLabel",
]
