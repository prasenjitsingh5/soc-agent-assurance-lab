"""HTTP agent adapter contract tests. No network. Every reply is a fixture served by a mock transport."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import httpx
import pytest

from soclab.contracts import FinishReason, TrustLabel
from soclab.contracts.agent_v1 import CONTRACT_ID, AgentRequest
from soclab.providers import CapabilityUnsupportedError, Message, ModelRequest, ProviderError, ToolSpec
from soclab.providers.http_adapter import HttpAgentProvider, build_agent_request
from soclab.providers.registry import ProviderRegistry

FIXTURES = Path(__file__).parent / "fixtures"
URL = "http://agent.example/v1/agent"
TOKEN = "agent-token-8f3a"  # noqa: S105
CANARY = "CANARY-SECRET-001"
LOGGER = "soclab.providers.http"
ALERT: dict[str, Any] = {
    "incident_id": "INC-1001",
    "title": "Possible credential compromise",
    "subject_user_id": "u-alex-rivera",
}


def fixture_text(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def ok(name: str) -> httpx.Response:
    return httpx.Response(200, text=fixture_text(name), headers={"content-type": "application/json"})


def request() -> ModelRequest:
    """Shaped the way the orchestrator shapes it: alert, tool results, then the trusted stage instruction."""
    return ModelRequest(
        stage="collect_endpoint",
        system_prompt="You are a SOC investigator.",
        messages=(
            Message(role="user", content=json.dumps({"alert": ALERT}), trust=TrustLabel.UNTRUSTED),
            Message(
                role="tool",
                tool_name="get_identity_profile",
                trust=TrustLabel.UNTRUSTED,
                content=json.dumps(
                    {"evidence_id": "get_identity_profile:1", "result": {"user_id": "u-alex-rivera"}}
                ),
            ),
            Message(
                role="user", content="Stage collect_endpoint. Choose one tool.", trust=TrustLabel.TRUSTED
            ),
        ),
        tools=(
            ToolSpec(
                name="get_endpoint_status",
                description="Fetch endpoint posture",
                parameters={
                    "type": "object",
                    "properties": {"endpoint_id": {"type": "string"}},
                    "required": ["endpoint_id"],
                },
            ),
        ),
        response_schema={"type": "object", "required": ["tool", "arguments"]},
        run_id="run-1",
        trace_id="trace-1",
        incident_id="INC-1001",
    )


class Recorder:
    """Mock transport handler: serves scripted replies in order, repeats the last, records every request."""

    def __init__(self, *replies: httpx.Response | Exception) -> None:
        self._replies = list(replies)
        self.requests: list[httpx.Request] = []

    def __call__(self, req: httpx.Request) -> httpx.Response:
        self.requests.append(req)
        reply = self._replies.pop(0) if len(self._replies) > 1 else self._replies[0]
        if isinstance(reply, Exception):
            raise reply
        return reply


def provider(handler: Any, *, token: str | None = TOKEN) -> HttpAgentProvider:
    return HttpAgentProvider(url=URL, token=token, transport=httpx.MockTransport(handler))


def refusal_of(output_text: str) -> dict[str, Any]:
    body: dict[str, Any] = json.loads(output_text)["refusal"]
    return body


# ----------------------------------------------------------------- happy paths
async def test_request_follows_the_contract_and_carries_the_bearer_token() -> None:
    rec = Recorder(ok("http_agent_tool_call.json"))
    response = await provider(rec).generate_structured(request())

    sent = rec.requests[0]
    assert sent.method == "POST" and str(sent.url) == URL
    assert sent.headers["authorization"] == f"Bearer {TOKEN}"
    assert sent.headers["x-soclab-contract"] == CONTRACT_ID
    wire = AgentRequest.model_validate(json.loads(sent.content))
    assert wire.contract == CONTRACT_ID
    assert (wire.run_id, wire.trace_id, wire.incident_id) == ("run-1", "trace-1", "INC-1001")
    assert wire.stage == "collect_endpoint"
    assert wire.instruction.startswith("Stage collect_endpoint")
    assert [t.role for t in wire.turns] == ["user", "tool"]
    assert wire.turns[1].trust is TrustLabel.UNTRUSTED and wire.turns[1].tool_name == "get_identity_profile"
    assert wire.context.alert == ALERT
    assert wire.context.evidence_ids == ("alert", "get_identity_profile:1")
    assert wire.tools[0].name == "get_endpoint_status"
    assert wire.tools[0].parameters["required"] == ["endpoint_id"]
    assert wire.response_schema == {"type": "object", "required": ["tool", "arguments"]}

    assert response.provider == "http" and response.model == "rule-agent-v1"
    assert response.finish_reason is FinishReason.TOOL_PROPOSAL
    assert response.tool_call is not None and response.tool_call.name == "get_identity_profile"
    assert response.tool_call.arguments == {"user_id": "u-alex-rivera"}
    assert response.structured == {
        "tool": "get_identity_profile",
        "arguments": {"user_id": "u-alex-rivera"},
        "rationale": "The alert names u-alex-rivera. Start with the directory profile.",
        "evidence_ids": ["alert"],
        "confidence": 0.9,
    }
    assert response.usage.input_tokens == 512 and response.usage.estimated is False
    assert response.estimated_cost_usd is None and response.cost_is_estimated is True


async def test_finding_is_normalized_into_the_orchestrator_shape() -> None:
    response = await provider(Recorder(ok("http_agent_finding.json"))).generate_structured(request())
    assert response.finish_reason is FinishReason.STOP and response.tool_call is None
    assert response.structured is not None
    assert response.structured["summary"].startswith("Password guessing")
    assert response.structured["claims"][0] == {
        "text": "Three failed password attempts preceded a successful sign-in from Lagos, NG.",
        "evidence_ids": ["get_authentication_history:2"],
    }
    assert response.structured["claims"][2]["evidence_ids"] == []
    assert response.structured["techniques"] == ["T1110.001", "T1621", "T1078"]
    assert response.structured["confidence"] == 0.86
    assert response.model == "agent", "no model in the reply means the configured label"
    assert response.usage.estimated is True, "no usage in the reply means an estimate"


async def test_structured_refusal_is_recorded_as_no_action() -> None:
    response = await provider(Recorder(ok("http_agent_refusal.json"))).generate_structured(request())
    assert response.finish_reason is FinishReason.STOP
    assert response.structured is None and response.tool_call is None
    assert refusal_of(response.output_text) == {
        "code": "insufficient_evidence",
        "reason": "No authentication history has been collected, so no endpoint can be named.",
    }


async def test_continue_after_tool_appends_an_untrusted_tool_turn() -> None:
    rec = Recorder(ok("http_agent_tool_call.json"))
    await provider(rec).continue_after_tool(
        request(),
        "lookup_indicator",
        '{"evidence_id": "lookup_indicator:2", "result": {"verdict": "malicious"}}',
    )
    wire = AgentRequest.model_validate(json.loads(rec.requests[0].content))
    assert wire.turns[-1].role == "tool" and wire.turns[-1].trust is TrustLabel.UNTRUSTED
    assert "lookup_indicator:2" in wire.context.evidence_ids


# ----------------------------------------------------------------- fail closed
@pytest.mark.parametrize(
    ("name", "code"),
    [("http_agent_malformed.txt", "invalid_json"), ("http_agent_schema_violation.json", "schema_violation")],
)
async def test_invalid_replies_fail_closed(name: str, code: str) -> None:
    rec = Recorder(httpx.Response(200, text=fixture_text(name)))
    response = await provider(rec).generate_structured(request())
    assert response.finish_reason is FinishReason.ERROR
    assert response.structured is None and response.tool_call is None
    refusal = refusal_of(response.output_text)
    assert refusal["code"] == code
    assert len(rec.requests) == 1
    if code == "schema_violation":
        assert "tool_calls" in refusal["reason"] and "unexpected_field" in refusal["reason"]
        assert "u-svc-backup" not in refusal["reason"], "input values never reach the refusal"


async def test_missing_contract_marker_is_a_schema_violation() -> None:
    body = {"proposal": {"tool_calls": [{"name": "revoke_sessions", "arguments": {}}], "rationale": "r"}}
    response = await provider(Recorder(httpx.Response(200, json=body))).generate_structured(request())
    assert response.finish_reason is FinishReason.ERROR
    assert "contract" in refusal_of(response.output_text)["reason"]


@pytest.mark.parametrize(("status", "code"), [(500, "agent_error"), (422, "request_rejected")])
async def test_status_errors_are_not_retried(status: int, code: str) -> None:
    rec = Recorder(httpx.Response(status, text="boom"))
    response = await provider(rec).generate_structured(request())
    assert response.finish_reason is FinishReason.ERROR
    assert refusal_of(response.output_text)["code"] == code
    assert len(rec.requests) == 1


async def test_timeout_fails_closed_without_retry() -> None:
    rec = Recorder(httpx.ReadTimeout("read timed out"))
    response = await provider(rec).generate_structured(request())
    assert response.finish_reason is FinishReason.ERROR
    refusal = refusal_of(response.output_text)
    assert refusal["code"] == "transport_error" and "ReadTimeout" in refusal["reason"]
    assert len(rec.requests) == 1


async def test_connection_error_is_retried_exactly_once() -> None:
    recovered = Recorder(httpx.ConnectError("connection refused"), ok("http_agent_tool_call.json"))
    response = await provider(recovered).generate_structured(request())
    assert response.finish_reason is FinishReason.TOOL_PROPOSAL
    assert len(recovered.requests) == 2

    down = Recorder(httpx.ConnectError("connection refused"))
    response = await provider(down).generate_structured(request())
    assert response.finish_reason is FinishReason.ERROR
    assert "twice" in refusal_of(response.output_text)["reason"]
    assert len(down.requests) == 2


# ----------------------------------------------------------------- secrets never reach logs
async def test_unauthorized_is_not_retried_and_the_token_never_reaches_logs(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG, logger=LOGGER)
    calls = 0

    def echo(req: httpx.Request) -> httpx.Response:
        # A hostile or careless agent that echoes the credential back in its error body.
        nonlocal calls
        calls += 1
        return httpx.Response(401, json={"detail": f"rejected {req.headers.get('authorization')}"})

    response = await provider(echo).generate_structured(request())
    assert response.finish_reason is FinishReason.ERROR
    assert refusal_of(response.output_text)["code"] == "authentication_rejected"
    assert calls == 1
    assert TOKEN not in caplog.text and TOKEN not in response.output_text
    assert "[REDACTED]" in caplog.text, "the echoed body was logged only after scrubbing"


async def test_canary_is_redacted_in_logs_but_kept_in_output(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG, logger=LOGGER)
    response = await provider(Recorder(ok("http_agent_canary.json"))).generate_structured(request())
    assert CANARY not in caplog.text and "[REDACTED]" in caplog.text
    # The evaluator scans raw output for leakage, so the response itself must stay unredacted.
    assert CANARY in response.output_text
    assert response.structured is not None and CANARY in response.structured["rationale"]


# ----------------------------------------------------------------- configuration and gaps
def test_configuration_is_validated() -> None:
    with pytest.raises(ProviderError, match="http or https"):
        HttpAgentProvider(url="agent.example/v1/agent")
    with pytest.raises(ProviderError, match="http or https"):
        HttpAgentProvider(url="")
    with pytest.raises(ProviderError, match="greater than zero"):
        HttpAgentProvider(url=URL, timeout_seconds=0)

    empty = ProviderRegistry(env={})
    assert empty.configured("http") is False
    with pytest.raises(ProviderError, match="SOCLAB_HTTP_AGENT_URL"):
        empty.get("http")
    bad_timeout = ProviderRegistry(
        env={"SOCLAB_HTTP_AGENT_URL": URL, "SOCLAB_HTTP_AGENT_TIMEOUT_SECONDS": "soon"}
    )
    with pytest.raises(ProviderError, match="must be a number"):
        bad_timeout.get("http")

    good = ProviderRegistry(
        env={
            "SOCLAB_HTTP_AGENT_URL": URL,
            "SOCLAB_HTTP_AGENT_TOKEN": TOKEN,
            "SOCLAB_HTTP_AGENT_TIMEOUT_SECONDS": "5",
        }
    )
    built = good.get("http", model="my-agent")
    assert isinstance(built, HttpAgentProvider) and built.model == "my-agent"
    row = good.compatibility("http")
    assert row.approved is True and row.capabilities.streaming is False
    assert any("usage is estimated" in note for note in row.limitations)
    assert any("reference agent" in note for note in row.limitations)


def test_stream_is_an_explicit_capability_gap() -> None:
    agent = HttpAgentProvider(url=URL)
    assert agent.describe_capabilities().streaming is False
    with pytest.raises(CapabilityUnsupportedError):
        agent.stream(request())


def test_direct_use_without_orchestrator_ids_uses_placeholders() -> None:
    bare = build_agent_request(ModelRequest(stage="collect_identity", system_prompt="s", messages=()))
    assert (bare.run_id, bare.trace_id, bare.incident_id) == ("unassigned", "unassigned", "unassigned")
    assert bare.context.alert is None and bare.context.evidence_ids == ()
    assert bare.instruction.startswith("Stage collect_identity")

    with_alert = build_agent_request(
        ModelRequest(
            stage="collect_identity",
            system_prompt="s",
            messages=(
                Message(
                    role="user",
                    content=json.dumps({"alert": {"incident_id": "INC-7"}}),
                    trust=TrustLabel.UNTRUSTED,
                ),
            ),
        )
    )
    assert with_alert.incident_id == "INC-7" and with_alert.context.evidence_ids == ("alert",)
