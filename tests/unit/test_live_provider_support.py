"""Paths that only matter once a real model sits behind the provider port."""

from __future__ import annotations

import pytest

from soclab.contracts import TrustLabel
from soclab.evaluator import CampaignConfig, load_attack_scenarios
from soclab.evaluator.runner import scenario_needs_mock
from soclab.orchestrator.workflow import (
    ACTION_SPECS,
    TOOL_SPECS,
    _plan_from_tool_call,
    stage_instruction,
)
from soclab.providers.base import ModelRequest
from soclab.providers.mock import MockProvider


def test_tool_specs_carry_argument_schemas() -> None:
    by_name = {t.name: t for t in ACTION_SPECS}
    assert len(TOOL_SPECS) == 5 and len(ACTION_SPECS) == 10
    assert by_name["revoke_sessions"].parameters["required"] == ["user_id"]
    assert by_name["get_authentication_history"].parameters["required"] == ["user_id"]
    assert by_name["disable_account"].parameters["additionalProperties"] is False


def test_stage_instructions_name_the_json_shape() -> None:
    for stage in ("collect_identity", "collect_siem"):
        text = stage_instruction(stage)
        assert '"tool"' in text and "search_siem_events" in text and "disable_account" not in text
    finding = stage_instruction("form_finding")
    assert "evidence_ids" in finding and "Do not invent ids" in finding
    action = stage_instruction("propose_action")
    assert "disable_account" in action and "rationale" in action


def test_native_tool_calls_become_plans() -> None:
    plain = _plan_from_tool_call("get_identity_profile", {"user_id": "u-alex-rivera"}, "")
    assert plain["tool"] == "get_identity_profile" and plain["arguments"] == {"user_id": "u-alex-rivera"}
    wrapped = _plan_from_tool_call(
        "get_identity_profile", {"tool": "lookup_indicator", "arguments": {"indicator": "198.51.100.77"}}, "x"
    )
    assert wrapped["tool"] == "lookup_indicator"
    assert wrapped["arguments"] == {"indicator": "198.51.100.77"}
    assert wrapped["rationale"] == "x"


def test_scripted_scenarios_are_excluded_for_live_providers() -> None:
    scenarios = load_attack_scenarios()
    live = [s.id for s in scenarios if not scenario_needs_mock(s)]
    assert live == [
        "ATK-001",
        "ATK-009",
        "ATK-013",
        "ATK-014",
        "ATK-015",
        "ATK-016",
        "ATK-017",
        "ATK-018",
        "ATK-019",
        "ATK-023",
        "ATK-024",
        "ATK-026",
        "ATK-028",
    ]
    assert "ATK-002" not in live and "ATK-011" not in live
    assert CampaignConfig(mode="protected").live is False
    assert CampaignConfig(mode="protected", provider_id="ollama").live is True


async def test_mock_still_ignores_instruction_message() -> None:
    from soclab.orchestrator.workflow import SYSTEM_PROMPT

    provider = MockProvider()
    request = ModelRequest(
        stage="collect_identity",
        system_prompt=SYSTEM_PROMPT,
        messages=(),
        tools=TOOL_SPECS,
        response_schema={"type": "object"},
    )
    response = await provider.generate_structured(request)
    assert response.structured == {"tool": "get_identity_profile", "arguments": {"user_id": "u-alex-rivera"}}


def test_live_campaign_with_unknown_provider_is_refused() -> None:
    import asyncio

    from soclab.evaluator import run_campaign
    from soclab.evidence import EvidenceRepository
    from soclab.providers import ProviderError

    config = CampaignConfig(mode="baseline", provider_id="nonexistent")
    with pytest.raises(ProviderError):
        asyncio.run(run_campaign(config, policy=None, repository=EvidenceRepository()))


def test_trust_label_on_instruction_is_trusted() -> None:
    from soclab.orchestrator.workflow import Message

    m = Message(role="user", content=stage_instruction("form_finding"), trust=TrustLabel.TRUSTED)
    assert m.trust is TrustLabel.TRUSTED
