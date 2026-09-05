"""The published JSON Schema files must match the soclab.agent.v1 Pydantic models exactly."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from soclab.contracts.agent_v1 import (
    CONTRACT_ID,
    SCHEMA_DIR,
    AgentProposal,
    AgentResponse,
    json_schemas,
    write_schemas,
)

REPO = Path(__file__).resolve().parents[2]
REGENERATE = "regenerate with: uv run python -m soclab.contracts.agent_v1"


def test_schema_dir_is_the_published_location() -> None:
    assert SCHEMA_DIR == REPO / "schemas" / "agent-v1"


@pytest.mark.parametrize("name", ["request", "response"])
def test_published_schema_matches_the_model(name: str) -> None:
    path = SCHEMA_DIR / f"{name}.schema.json"
    assert path.exists(), f"{path} is missing; {REGENERATE}"
    on_disk = json.loads(path.read_text(encoding="utf-8"))
    assert on_disk == json_schemas()[name], f"{path.name} drifted from the model; {REGENERATE}"
    assert on_disk["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert on_disk["$id"].endswith(f"agent-v1/{name}.schema.json")
    assert on_disk["additionalProperties"] is False
    assert on_disk["properties"]["contract"]["const"] == CONTRACT_ID
    assert "contract" in on_disk["required"] or name == "request"


def test_write_schemas_is_deterministic_and_matches_the_repository(tmp_path: Path) -> None:
    first = {p.name: p.read_text(encoding="utf-8") for p in write_schemas(tmp_path)}
    second = {p.name: p.read_text(encoding="utf-8") for p in write_schemas(tmp_path)}
    assert first == second
    assert set(first) == {"request.schema.json", "response.schema.json"}
    for name, text in first.items():
        assert text == (SCHEMA_DIR / name).read_text(encoding="utf-8"), f"{name} drifted; {REGENERATE}"


def test_response_contract_rules() -> None:
    refusal = {"contract": CONTRACT_ID, "refusal": {"code": "policy", "reason": "not during business hours"}}
    assert AgentResponse.model_validate(refusal).refusal is not None

    call = {
        "tool_calls": [{"name": "revoke_sessions", "arguments": {"user_id": "u-alex-rivera"}}],
        "rationale": "r",
    }
    with pytest.raises(ValidationError, match="exactly one of proposal or refusal"):
        AgentResponse.model_validate({**refusal, "proposal": call})
    with pytest.raises(ValidationError, match="exactly one of proposal or refusal"):
        AgentResponse.model_validate({"contract": CONTRACT_ID})
    with pytest.raises(ValidationError, match="exactly one of tool_calls or finding"):
        AgentProposal.model_validate({"rationale": "nothing to do"})
    with pytest.raises(ValidationError, match="contract"):
        AgentResponse.model_validate({"contract": "soclab.agent.v2", "proposal": call})
    with pytest.raises(ValidationError, match="tool_calls"):
        AgentProposal.model_validate({"tool_calls": [call["tool_calls"][0]] * 2, "rationale": "two"})
    with pytest.raises(ValidationError, match="name"):
        AgentProposal.model_validate(
            {"tool_calls": [{"name": "Disable-Account", "arguments": {}}], "rationale": "r"}
        )
    with pytest.raises(ValidationError, match="code"):
        AgentResponse.model_validate({"contract": CONTRACT_ID, "refusal": {"code": "tired", "reason": "no"}})
