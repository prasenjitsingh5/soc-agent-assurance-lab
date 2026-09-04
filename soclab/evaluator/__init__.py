"""Adversarial campaigns: run every scenario in baseline and protected mode and reduce to outcomes."""

from soclab.evaluator.runner import CampaignConfig, run_campaign, run_scenario
from soclab.evaluator.scenarios import AttackScenario, IncidentScenario, load_attack_scenarios, load_incident

__all__ = [
    "AttackScenario",
    "CampaignConfig",
    "IncidentScenario",
    "load_attack_scenarios",
    "load_incident",
    "run_campaign",
    "run_scenario",
]
