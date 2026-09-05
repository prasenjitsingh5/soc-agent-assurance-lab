"""The ``soclab.agent.v1`` contract: what the lab sends to an external agent and what it accepts back.

An agent behind an HTTP endpoint receives one :class:`AgentRequest` per stage and
answers with one :class:`AgentResponse`. A response carries either a proposal or a
refusal, never both, and a proposal carries either one tool call or one finding.
The orchestrator maps both onto the same canonical shapes it already validates.

JSON Schema files for both models live in ``schemas/agent-v1``. Regenerate them
with ``python -m soclab.contracts.agent_v1``. A test fails when the files drift
from these models, so the published schema and the validator never disagree.
"""

from __future__ import annotations

import json
from enum import StrEnum
from pathlib import Path
from typing import Any, Final, Literal

from pydantic import Field, model_validator

from soclab.contracts.enums import TrustLabel
from soclab.contracts.models import StrictModel

CONTRACT_ID: Final = "soclab.agent.v1"
SCHEMA_DIALECT = "https://json-schema.org/draft/2020-12/schema"
SCHEMA_ID_BASE = "https://github.com/prasenjitsingh5/soc-agent-assurance-lab/schemas/agent-v1/"
SCHEMA_DIR = Path(__file__).resolve().parents[2] / "schemas" / "agent-v1"

_NAME = r"^[a-z][a-z0-9_]*$"


# --------------------------------------------------------------------------- request
class AgentTurn(StrictModel):
    """One prior message in the investigation. Tool output is always labeled untrusted."""

    role: Literal["system", "user", "assistant", "tool"]
    content: str
    trust: TrustLabel = TrustLabel.TRUSTED
    tool_name: str | None = None


class AgentTool(StrictModel):
    """A tool the agent may name at this stage, with the JSON Schema of its arguments."""

    name: str = Field(pattern=_NAME)
    description: str = Field(min_length=1)
    parameters: dict[str, Any] = Field(description="JSON Schema for the arguments object")


class AgentContext(StrictModel):
    """The incident context the orchestrator has built so far."""

    alert: dict[str, Any] | None = Field(
        default=None, description="The alert as the orchestrator presented it. Untrusted data."
    )
    evidence_ids: tuple[str, ...] = Field(
        default=(),
        description="Evidence ids seen so far. A finding may cite only these; anything else is unsupported.",
    )


class AgentRequest(StrictModel):
    """One stage of the bounded investigation, sent as the POST body."""

    contract: Literal["soclab.agent.v1"] = CONTRACT_ID
    run_id: str = Field(min_length=1)
    trace_id: str = Field(min_length=1)
    incident_id: str = Field(min_length=1)
    stage: str = Field(pattern=_NAME)
    instruction: str = Field(
        min_length=1, description="What the orchestrator wants at this stage and the shape it expects back."
    )
    system_prompt: str
    context: AgentContext
    tools: tuple[AgentTool, ...] = ()
    response_schema: dict[str, Any] | None = None
    turns: tuple[AgentTurn, ...] = ()
    max_output_tokens: int = Field(ge=1)
    temperature: float = Field(ge=0.0, le=2.0)


# --------------------------------------------------------------------------- response
class AgentToolCall(StrictModel):
    """One tool the agent wants run, with arguments matching that tool's schema."""

    name: str = Field(pattern=_NAME)
    arguments: dict[str, Any]


class AgentClaim(StrictModel):
    """A statement in a finding. Every id it cites must have appeared in a tool result."""

    text: str = Field(min_length=1)
    evidence_ids: tuple[str, ...] = ()


class AgentFinding(StrictModel):
    """The agent's account of what happened, returned at the form_finding stage."""

    summary: str = Field(min_length=1)
    claims: tuple[AgentClaim, ...] = ()
    techniques: tuple[str, ...] = Field(default=(), description="ATT&CK technique ids, for example T1078")


class AgentProposal(StrictModel):
    """What the agent wants done. Exactly one of tool_calls or finding is present."""

    tool_calls: tuple[AgentToolCall, ...] = Field(
        default=(), max_length=1, description="At most one call per turn in this contract version."
    )
    finding: AgentFinding | None = None
    rationale: str = Field(min_length=1, max_length=2000)
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    evidence_ids: tuple[str, ...] = Field(default=(), description="Evidence ids that support the proposal.")

    @model_validator(mode="after")
    def _exactly_one_shape(self) -> AgentProposal:
        if bool(self.tool_calls) == (self.finding is not None):
            msg = "a proposal carries exactly one of tool_calls or finding"
            raise ValueError(msg)
        return self


class RefusalCode(StrEnum):
    """Why an agent declined to propose anything at this stage."""

    INSUFFICIENT_EVIDENCE = "insufficient_evidence"
    OUT_OF_SCOPE = "out_of_scope"
    UNSUPPORTED_STAGE = "unsupported_stage"
    POLICY = "policy"
    ERROR = "error"


class AgentRefusal(StrictModel):
    """A structured no. The orchestrator records it and takes no action."""

    code: RefusalCode
    reason: str = Field(min_length=1, max_length=2000)


class AgentUsage(StrictModel):
    """Token counts if the agent knows them. Absent usage is estimated and labeled as such."""

    input_tokens: int = Field(ge=0)
    output_tokens: int = Field(ge=0)


class AgentResponse(StrictModel):
    """The POST reply. Exactly one of proposal or refusal is present."""

    contract: Literal["soclab.agent.v1"]
    proposal: AgentProposal | None = None
    refusal: AgentRefusal | None = None
    model: str | None = Field(
        default=None,
        min_length=1,
        max_length=200,
        description="Optional label for the model or version behind the agent. Recorded on every turn.",
    )
    usage: AgentUsage | None = None

    @model_validator(mode="after")
    def _exactly_one_outcome(self) -> AgentResponse:
        if (self.proposal is None) == (self.refusal is None):
            msg = "a response carries exactly one of proposal or refusal"
            raise ValueError(msg)
        return self


# --------------------------------------------------------------------------- schema export
def json_schemas() -> dict[str, dict[str, Any]]:
    """The published JSON Schema for the request and the response, keyed by file stem."""
    out: dict[str, dict[str, Any]] = {}
    for name, model in (("request", AgentRequest), ("response", AgentResponse)):
        schema = model.model_json_schema()
        out[name] = {"$schema": SCHEMA_DIALECT, "$id": f"{SCHEMA_ID_BASE}{name}.schema.json", **schema}
    return out


def write_schemas(directory: Path = SCHEMA_DIR) -> tuple[Path, ...]:
    """Write ``request.schema.json`` and ``response.schema.json`` into ``directory``."""
    directory.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for name, schema in json_schemas().items():
        path = directory / f"{name}.schema.json"
        path.write_text(json.dumps(schema, indent=2) + "\n", encoding="utf-8")
        written.append(path)
    return tuple(written)


if __name__ == "__main__":
    for written_path in write_schemas():
        print(written_path)  # noqa: T201
