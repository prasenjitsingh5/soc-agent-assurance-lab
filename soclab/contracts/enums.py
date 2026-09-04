"""Closed vocabularies. Unknown values fail validation; nothing is coerced."""

from enum import StrEnum


class DecisionOutcome(StrEnum):
    """The four outcomes a policy decision point may return. Exact per the design."""

    ALLOW = "allow"
    ALLOW_WITH_OBLIGATIONS = "allow_with_obligations"
    REQUIRE_APPROVAL = "require_approval"
    DENY = "deny"


class RiskTier(StrEnum):
    """Impact class of a tool. Drives approval requirements and gate checks."""

    READ_ONLY = "read_only"
    LOW = "low"
    HIGH = "high"


class AuthorityLevel(StrEnum):
    """Operational authority an agent may hold. Promotion requires evidence."""

    L1_OBSERVE = "L1"
    L2_INVESTIGATE = "L2"
    L3_RECOMMEND = "L3"
    L4_ACT_WITH_APPROVAL = "L4"
    L5_BOUNDED_AUTONOMY = "L5"


class TrustLabel(StrEnum):
    """Provenance class of any input the model sees."""

    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"


class ApprovalDecision(StrEnum):
    APPROVED = "approved"
    REJECTED = "rejected"


class ExecutionStatus(StrEnum):
    PROPOSED = "proposed"
    DENIED = "denied"
    AWAITING_APPROVAL = "awaiting_approval"
    EXECUTED = "executed"
    FAILED_CLOSED = "failed_closed"


class FinishReason(StrEnum):
    """Normalized provider finish reason."""

    STOP = "stop"
    TOOL_PROPOSAL = "tool_proposal"
    LENGTH = "length"
    CONTENT_FILTER = "content_filter"
    ERROR = "error"
