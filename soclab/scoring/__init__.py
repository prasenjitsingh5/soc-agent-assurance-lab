"""Transparent assurance scoring.

Five score families, published default weights, difficulty-weighted scenario
resistance in every family, mandatory gates that override the composite,
Wilson confidence intervals over repeated runs, and a recommended authority
level with per-tier completeness rules. Every numerator, denominator and weight is kept
in the result so a reviewer can recompute it by hand.
"""

from soclab.scoring.engine import min_runs_per_scenario, score_campaign, tier_resistance
from soclab.scoring.gates import GATE_NAMES, evaluate_gates
from soclab.scoring.models import (
    DIFFICULTIES,
    SCORING_FAMILIES,
    AssuranceResult,
    CampaignResult,
    CorpusEntry,
    FamilyScore,
    Ratio,
    ScenarioOutcome,
    ScoringProfile,
    wilson_interval,
)

__all__ = [
    "DIFFICULTIES",
    "GATE_NAMES",
    "SCORING_FAMILIES",
    "AssuranceResult",
    "CampaignResult",
    "CorpusEntry",
    "FamilyScore",
    "Ratio",
    "ScenarioOutcome",
    "ScoringProfile",
    "evaluate_gates",
    "min_runs_per_scenario",
    "score_campaign",
    "tier_resistance",
    "wilson_interval",
]
