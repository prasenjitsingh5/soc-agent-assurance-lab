"""Bring-your-own-agent provider over HTTP.

The lab POSTs one ``soclab.agent.v1`` request per stage to a URL the operator
configures and validates the reply strictly against
:class:`~soclab.contracts.agent_v1.AgentResponse`. Anything that is not a valid
reply, including a transport failure, a non-2xx status, unparseable JSON or a
schema violation, becomes a refusal with finish reason ``error``. The
orchestrator treats that as no structured output and takes no action.

The bearer token, when set, travels only in the ``Authorization`` header. Every
log line passes through :func:`soclab.redaction.redact_secrets` and then has the
token literal removed, so neither canary values nor the credential reach a log.
"""

from __future__ import annotations

import json
import logging
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Any

import httpx
from pydantic import ValidationError

from soclab.contracts import FinishReason, ProviderCapabilities, TokenUsage, TrustLabel
from soclab.contracts.agent_v1 import (
    CONTRACT_ID,
    AgentContext,
    AgentRequest,
    AgentResponse,
    AgentTool,
    AgentTurn,
)
from soclab.providers._shared import Timer
from soclab.providers.base import (
    CapabilityUnsupportedError,
    Message,
    ModelRequest,
    ModelResponse,
    ProviderError,
    ToolCall,
    estimate_tokens,
)
from soclab.redaction import redact_secrets

ADAPTER_VERSION = "1.0.0"
DEFAULT_TIMEOUT_SECONDS = 30.0
UNASSIGNED = "unassigned"

_RETRY_ONCE_ON = (httpx.ConnectError, httpx.ConnectTimeout)
_LOG_BODY_LIMIT = 2000

log = logging.getLogger("soclab.providers.http")


@dataclass(frozen=True)
class _Failure:
    """Why the adapter refused on the agent's behalf. Never carries the response body."""

    code: str
    reason: str


def _json_object(text: str) -> dict[str, Any] | None:
    try:
        value = json.loads(text)
    except ValueError:
        return None
    return value if isinstance(value, dict) else None


def _alert_from(turns: list[Message]) -> dict[str, Any] | None:
    """The orchestrator opens every run with ``{"alert": {...}}`` as an untrusted user message."""
    for turn in turns:
        if turn.role != "user":
            continue
        body = _json_object(turn.content)
        if body is not None and isinstance(body.get("alert"), dict):
            alert: dict[str, Any] = body["alert"]
            return alert
        return None
    return None


def _evidence_ids(turns: list[Message]) -> list[str]:
    ids: list[str] = []
    for turn in turns:
        if turn.role != "tool":
            continue
        body = _json_object(turn.content)
        if body is not None and isinstance(body.get("evidence_id"), str):
            ids.append(body["evidence_id"])
    return ids


def build_agent_request(request: ModelRequest) -> AgentRequest:
    """Translate the canonical request into the wire contract.

    The trailing trusted user message is the stage instruction the orchestrator
    appends; it becomes ``instruction`` and is removed from ``turns``.
    """
    turns = list(request.messages)
    instruction = ""
    if turns and turns[-1].role == "user" and turns[-1].trust is TrustLabel.TRUSTED:
        instruction = turns.pop().content
    alert = _alert_from(turns)
    evidence = _evidence_ids(turns)
    incident_id = request.incident_id
    if incident_id is None and alert is not None and isinstance(alert.get("incident_id"), str):
        incident_id = alert["incident_id"]
    return AgentRequest(
        run_id=request.run_id or UNASSIGNED,
        trace_id=request.trace_id or UNASSIGNED,
        incident_id=incident_id or UNASSIGNED,
        stage=request.stage,
        instruction=instruction or f"Stage {request.stage}. Answer per the {CONTRACT_ID} contract.",
        system_prompt=request.system_prompt,
        context=AgentContext(
            alert=alert, evidence_ids=tuple(["alert", *evidence] if alert is not None else evidence)
        ),
        tools=tuple(
            AgentTool(name=t.name, description=t.description, parameters=t.parameters) for t in request.tools
        ),
        response_schema=request.response_schema,
        turns=tuple(
            AgentTurn(role=t.role, content=t.content, trust=t.trust, tool_name=t.tool_name) for t in turns
        ),
        max_output_tokens=request.max_output_tokens,
        temperature=request.temperature,
    )


def _replace_literal(value: Any, literal: str) -> Any:
    if isinstance(value, str):
        return value.replace(literal, "[REDACTED]")
    if isinstance(value, dict):
        return {k: _replace_literal(v, literal) for k, v in value.items()}
    if isinstance(value, list):
        return [_replace_literal(v, literal) for v in value]
    if isinstance(value, tuple):
        return tuple(_replace_literal(v, literal) for v in value)
    return value


def _validation_summary(exc: ValidationError) -> str:
    """Field paths and messages only. Input values never reach the summary."""
    parts = []
    for error in exc.errors(include_url=False, include_input=False)[:5]:
        location = ".".join(str(p) for p in error.get("loc", ())) or "body"
        parts.append(f"{location}: {error.get('msg', 'invalid')}")
    return f"{exc.error_count()} validation error(s): " + "; ".join(parts)


class HttpAgentProvider:
    """Provider id ``http``. One POST per stage, strict validation, fail closed."""

    provider_id = "http"

    def __init__(
        self,
        *,
        url: str,
        model: str = "agent",
        token: str | None = None,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        try:
            parsed = httpx.URL(url)
        except httpx.InvalidURL as exc:
            msg = f"SOCLAB_HTTP_AGENT_URL is not a valid URL: {exc}"
            raise ProviderError(msg) from exc
        if parsed.scheme not in {"http", "https"} or not parsed.host:
            msg = "SOCLAB_HTTP_AGENT_URL must be an absolute http or https URL"
            raise ProviderError(msg)
        if timeout_seconds <= 0:
            msg = "SOCLAB_HTTP_AGENT_TIMEOUT_SECONDS must be greater than zero"
            raise ProviderError(msg)
        self.model = model
        self._url = str(parsed)
        self._token = token or None
        self._timeout = timeout_seconds
        self._transport = transport

    # ------------------------------------------------------------- capabilities
    def describe_capabilities(self) -> ProviderCapabilities:
        # Usage is optional in the contract, so the adapter declares it absent and labels estimates.
        return ProviderCapabilities(
            tool_calling=True,
            structured_output=True,
            streaming=False,
            usage_reporting=False,
            multimodal_input=False,
        )

    def count_usage(self, request: ModelRequest) -> TokenUsage:
        text = request.system_prompt + "".join(m.content for m in request.messages)
        return TokenUsage(input_tokens=estimate_tokens(text), output_tokens=0, estimated=True)

    def stream(self, request: ModelRequest) -> AsyncIterator[str]:
        msg = "http agent provider does not stream"
        raise CapabilityUnsupportedError(msg)

    # ------------------------------------------------------------- generation
    async def generate(self, request: ModelRequest) -> ModelResponse:
        return await self._call(request)

    async def generate_structured(self, request: ModelRequest) -> ModelResponse:
        return await self._call(request)

    async def request_tool(self, request: ModelRequest) -> ModelResponse:
        return await self._call(request)

    async def continue_after_tool(
        self, request: ModelRequest, tool_name: str, tool_result: str
    ) -> ModelResponse:
        extended = request.model_copy(
            update={
                "messages": (
                    *request.messages,
                    Message(
                        role="tool", tool_name=tool_name, content=tool_result, trust=TrustLabel.UNTRUSTED
                    ),
                )
            }
        )
        return await self._call(extended)

    # ------------------------------------------------------------- transport
    def _scrub(self, value: Any) -> Any:
        clean = redact_secrets(value)
        return _replace_literal(clean, self._token) if self._token else clean

    def _headers(self) -> dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "X-Soclab-Contract": CONTRACT_ID,
        }
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        return headers

    async def _post(self, payload: dict[str, Any]) -> httpx.Response | _Failure:
        """One POST, retried once on a connection-level failure and never on a status code."""
        retried = False
        while True:
            try:
                async with httpx.AsyncClient(timeout=self._timeout, transport=self._transport) as client:
                    return await client.post(self._url, json=payload, headers=self._headers())
            except _RETRY_ONCE_ON as exc:
                if retried:
                    return _Failure("transport_error", f"connection failed twice: {type(exc).__name__}")
                retried = True
                log.warning("agent connection failed (%s); retrying once", type(exc).__name__)
            except httpx.HTTPError as exc:
                return _Failure("transport_error", f"{type(exc).__name__}: {self._scrub(str(exc))}")

    async def _call(self, request: ModelRequest) -> ModelResponse:
        payload = build_agent_request(request).model_dump(mode="json")
        log.debug("agent request stage=%s body=%s", request.stage, self._scrub(payload))
        with Timer() as timer:
            outcome = await self._post(payload)
        if isinstance(outcome, _Failure):
            return self._refused(request, outcome, timer.elapsed_ms)
        return self._normalize(request, outcome, timer.elapsed_ms)

    # ------------------------------------------------------------- normalization
    def _normalize(self, request: ModelRequest, response: httpx.Response, latency_ms: int) -> ModelResponse:
        status = response.status_code
        log.debug(
            "agent response stage=%s status=%s body=%s",
            request.stage,
            status,
            self._scrub(response.text[:_LOG_BODY_LIMIT]),
        )
        failure = _status_failure(status)
        if failure is not None:
            return self._refused(request, failure, latency_ms)
        body = _json_object(response.text)
        if body is None:
            return self._refused(
                request, _Failure("invalid_json", "agent reply is not a JSON object"), latency_ms
            )
        try:
            reply = AgentResponse.model_validate(body)
        except ValidationError as exc:
            return self._refused(request, _Failure("schema_violation", _validation_summary(exc)), latency_ms)

        if reply.refusal is not None:
            text = json.dumps({"refusal": reply.refusal.model_dump(mode="json")}, sort_keys=True)
            log.info("agent refused stage=%s code=%s", request.stage, reply.refusal.code.value)
            return self._response(request, reply, FinishReason.STOP, text, None, None, latency_ms)

        proposal = reply.proposal
        if proposal is None:  # pragma: no cover - excluded by the model validator
            msg = "agent reply carries neither proposal nor refusal"
            raise ProviderError(msg)
        if proposal.finding is not None:
            structured: dict[str, Any] = {
                "summary": proposal.finding.summary,
                "claims": [
                    {"text": c.text, "evidence_ids": list(c.evidence_ids)} for c in proposal.finding.claims
                ],
                "techniques": list(proposal.finding.techniques),
                "confidence": proposal.confidence if proposal.confidence is not None else 0.0,
            }
            return self._response(
                request, reply, FinishReason.STOP, response.text, structured, None, latency_ms
            )
        call = proposal.tool_calls[0]
        structured = {
            "tool": call.name,
            "arguments": dict(call.arguments),
            "rationale": proposal.rationale,
            "evidence_ids": list(proposal.evidence_ids),
        }
        if proposal.confidence is not None:
            structured["confidence"] = proposal.confidence
        tool_call = ToolCall(name=call.name, arguments=dict(call.arguments))
        return self._response(
            request, reply, FinishReason.TOOL_PROPOSAL, response.text, structured, tool_call, latency_ms
        )

    def _usage(self, request: ModelRequest, reply: AgentResponse | None, text: str) -> TokenUsage:
        if reply is not None and reply.usage is not None:
            return TokenUsage(
                input_tokens=reply.usage.input_tokens,
                output_tokens=reply.usage.output_tokens,
                estimated=False,
            )
        return TokenUsage(
            input_tokens=self.count_usage(request).input_tokens,
            output_tokens=estimate_tokens(text),
            estimated=True,
        )

    def _response(
        self,
        request: ModelRequest,
        reply: AgentResponse,
        finish: FinishReason,
        text: str,
        structured: dict[str, Any] | None,
        tool_call: ToolCall | None,
        latency_ms: int,
    ) -> ModelResponse:
        # The raw body is kept as output_text on purpose: the evaluator scans it for canary leakage.
        return ModelResponse(
            provider=self.provider_id,
            model=reply.model or self.model,
            finish_reason=finish,
            output_text=text,
            structured=structured,
            tool_call=tool_call,
            usage=self._usage(request, reply, text),
            latency_ms=latency_ms,
            estimated_cost_usd=None,
            cost_is_estimated=True,
        )

    def _refused(self, request: ModelRequest, failure: _Failure, latency_ms: int) -> ModelResponse:
        """Fail closed: a refusal the orchestrator records as an error turn with no structured output."""
        reason = str(self._scrub(failure.reason))
        log.warning("agent turn refused stage=%s code=%s reason=%s", request.stage, failure.code, reason)
        text = json.dumps({"refusal": {"code": failure.code, "reason": reason}}, sort_keys=True)
        return ModelResponse(
            provider=self.provider_id,
            model=self.model,
            finish_reason=FinishReason.ERROR,
            output_text=text,
            structured=None,
            tool_call=None,
            usage=self._usage(request, None, text),
            latency_ms=latency_ms,
            estimated_cost_usd=None,
            cost_is_estimated=True,
        )


def _status_failure(status: int) -> _Failure | None:
    if 200 <= status < 300:
        return None
    if status in {401, 403}:
        return _Failure("authentication_rejected", f"agent rejected the credentials with HTTP {status}")
    if 400 <= status < 500:
        return _Failure("request_rejected", f"agent rejected the request with HTTP {status}")
    if status >= 500:
        return _Failure("agent_error", f"agent failed with HTTP {status}")
    return _Failure("unexpected_status", f"agent answered with HTTP {status}")
