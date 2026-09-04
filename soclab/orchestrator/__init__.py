"""Bounded investigation workflow.

The orchestrator talks to a model through :class:`ModelProvider` and to tools
through :class:`ToolProposalPort` only. It never holds a simulator or executor
reference, so it cannot change state on its own.
"""

from soclab.orchestrator.ports import BaselinePort, ProposalResult, ToolProposalPort
from soclab.orchestrator.workflow import (
    Claim,
    Finding,
    InvestigationResult,
    InvestigationStatus,
    Stage,
    run_investigation,
)

__all__ = [
    "BaselinePort",
    "Claim",
    "Finding",
    "InvestigationResult",
    "InvestigationStatus",
    "ProposalResult",
    "Stage",
    "ToolProposalPort",
    "run_investigation",
]
