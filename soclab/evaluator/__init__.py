"""Campaigns: run every attack and benign control in baseline and protected mode and reduce to outcomes."""

from soclab.evaluator.runner import CampaignConfig, run_campaign, run_scenario
from soclab.evaluator.scenarios import (
    AttackScenario,
    IncidentScenario,
    load_attack_scenarios,
    load_benign_scenarios,
    load_incident,
    load_scenario_corpus,
)

__all__ = [
    "AttackScenario",
    "CampaignConfig",
    "IncidentScenario",
    "load_attack_scenarios",
    "load_benign_scenarios",
    "load_incident",
    "load_scenario_corpus",
    "run_campaign",
    "run_scenario",
]
