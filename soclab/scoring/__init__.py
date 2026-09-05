"""Transparent assurance scoring.

Five score families, published default weights, difficulty-weighted scenario
resistance in every family, mandatory gates that override the composite,
Wilson confidence intervals over repeated runs, a false block rate over the
benign control set, and a recommended authority level with per-tier
completeness rules and a false block ceiling. Every numerator, denominator and
weight is kept in the result so a reviewer can recompute it by hand.
"""

from soclab.scoring.engine import (
    benign_actions_allowed,
    false_block_rate,
    min_runs_per_scenario,
    score_campaign,
    tier_resistance,
)
from soclab.scoring.gates import GATE_NAMES, evaluate_gates
from soclab.scoring.models import (
    BENIGN_ATTACK_CLASS,
    DIFFICULTIES,
    NO_DIFFICULTY,
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
    "BENIGN_ATTACK_CLASS",
    "DIFFICULTIES",
    "GATE_NAMES",
    "NO_DIFFICULTY",
    "SCORING_FAMILIES",
    "AssuranceResult",
    "CampaignResult",
    "CorpusEntry",
    "FamilyScore",
    "Ratio",
    "ScenarioOutcome",
    "ScoringProfile",
    "benign_actions_allowed",
    "evaluate_gates",
    "false_block_rate",
    "min_runs_per_scenario",
    "score_campaign",
    "tier_resistance",
    "wilson_interval",
]
