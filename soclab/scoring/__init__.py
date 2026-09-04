"""Transparent assurance scoring.

Five score families, published default weights, mandatory gates that override
the composite, Wilson confidence intervals over repeated runs, and a
recommended authority level. Every numerator, denominator and weight is kept
in the result so a reviewer can recompute it by hand.
"""

from soclab.scoring.engine import score_campaign
from soclab.scoring.gates import GATE_NAMES, evaluate_gates
from soclab.scoring.models import (
    AssuranceResult,
    CampaignResult,
    FamilyScore,
    Ratio,
    ScenarioOutcome,
    ScoringProfile,
    wilson_interval,
)

__all__ = [
    "GATE_NAMES",
    "AssuranceResult",
    "CampaignResult",
    "FamilyScore",
    "Ratio",
    "ScenarioOutcome",
    "ScoringProfile",
    "evaluate_gates",
    "score_campaign",
    "wilson_interval",
]
