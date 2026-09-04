"""Ollama local models over the native HTTP API. No SDK, no credentials."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from typing import Any

import httpx

from soclab.contracts import FinishReason, ProviderCapabilities, TokenUsage, TrustLabel
from soclab.providers._shared import (
    Timer,
    build_response,
    openai_style_messages,
    openai_style_tools,
    parse_tool_arguments,
)
from soclab.providers.base import (
    MalformedResponseError,
    Message,
    ModelRequest,
    ModelResponse,
    ProviderError,
    ToolCall,
    estimate_tokens,
)

ADAPTER_VERSION = "1.0.0"


class OllamaProvider:
    provider_id = "ollama"

    def __init__(
        self,
        *,
        model: str,
        base_url: str = "http://localhost:11434",
        timeout_seconds: float = 120.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.model = model
        self._url = base_url.rstrip("/")
        self._timeout = timeout_seconds
        self._transport = transport

    def describe_capabilities(self) -> ProviderCapabilities:
        # Tool calling depends on the model; the adapter declares it and the runtime validates results.
        return ProviderCapabilities(
            tool_calling=True,
            structured_output=True,
            streaming=True,
            usage_reporting=True,
            multimodal_input=False,
        )

    def count_usage(self, request: ModelRequest) -> TokenUsage:
        text = request.system_prompt + "".join(m.content for m in request.messages)
        return TokenUsage(input_tokens=estimate_tokens(text), output_tokens=0, estimated=True)

    def _payload(
        self, request: ModelRequest, *, structured: bool, with_tools: bool, stream: bool
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": openai_style_messages(request),
            "stream": stream,
            "options": {"temperature": request.temperature, "num_predict": request.max_output_tokens},
        }
        if structured:
            payload["format"] = "json"
        if with_tools and request.tools:
            payload["tools"] = openai_style_tools(request.tools)
        return payload

    async def _call(self, payload: dict[str, Any]) -> dict[str, Any]:
        try:
            async with httpx.AsyncClient(timeout=self._timeout, transport=self._transport) as client:
                response = await client.post(self._url + "/api/chat", json=payload)
                response.raise_for_status()
                body = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            msg = f"ollama request failed: {type(exc).__name__}: {exc}"
            raise ProviderError(msg) from exc
        if not isinstance(body, dict):
            msg = "ollama returned a non-object body"
            raise MalformedResponseError(msg)
        return body

    def _normalize(self, body: dict[str, Any], *, want_structured: bool, latency_ms: int) -> ModelResponse:
        message = body.get("message")
        if not isinstance(message, dict):
            msg = "ollama response has no message"
            raise MalformedResponseError(msg)
        tool_call: ToolCall | None = None
        calls = message.get("tool_calls") or []
        if calls:
            fn = calls[0].get("function", {})
            tool_call = ToolCall(
                name=str(fn.get("name", "")), arguments=parse_tool_arguments(fn.get("arguments", {}))
            )
        text = str(message.get("content") or "")
        done_reason = str(body.get("done_reason", "stop"))
        finish = {"stop": FinishReason.STOP, "length": FinishReason.LENGTH}.get(
            done_reason, FinishReason.ERROR
        )
        if tool_call is not None:
            finish = FinishReason.TOOL_PROPOSAL
        if "prompt_eval_count" in body and "eval_count" in body:
            usage = TokenUsage(
                input_tokens=int(body["prompt_eval_count"]),
                output_tokens=int(body["eval_count"]),
                estimated=False,
            )
        else:
            usage = TokenUsage(input_tokens=0, output_tokens=estimate_tokens(text), estimated=True)
        response = build_response(
            provider=self.provider_id,
            model=str(body.get("model") or self.model),
            finish=finish,
            text=text,
            tool_call=tool_call,
            usage=usage,
            latency_ms=latency_ms,
            want_structured=want_structured,
        )
        # Local models have no list price; cost is reported as zero and labeled estimated.
        return response.model_copy(update={"estimated_cost_usd": 0.0, "cost_is_estimated": True})

    async def generate(self, request: ModelRequest) -> ModelResponse:
        with Timer() as t:
            body = await self._call(self._payload(request, structured=False, with_tools=False, stream=False))
        return self._normalize(body, want_structured=False, latency_ms=t.elapsed_ms)

    async def generate_structured(self, request: ModelRequest) -> ModelResponse:
        with Timer() as t:
            body = await self._call(
                self._payload(request, structured=True, with_tools=bool(request.tools), stream=False)
            )
        return self._normalize(body, want_structured=True, latency_ms=t.elapsed_ms)

    async def request_tool(self, request: ModelRequest) -> ModelResponse:
        with Timer() as t:
            body = await self._call(self._payload(request, structured=False, with_tools=True, stream=False))
        return self._normalize(body, want_structured=False, latency_ms=t.elapsed_ms)

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
        return await self.generate_structured(extended)

    async def stream(self, request: ModelRequest) -> AsyncIterator[str]:
        payload = self._payload(request, structured=False, with_tools=False, stream=True)
        try:
            async with (
                httpx.AsyncClient(timeout=self._timeout, transport=self._transport) as client,
                client.stream("POST", self._url + "/api/chat", json=payload) as response,
            ):
                response.raise_for_status()
                async for line in response.aiter_lines():
                    if not line:
                        continue
                    chunk = json.loads(line)
                    text = chunk.get("message", {}).get("content")
                    if text:
                        yield str(text)
        except (httpx.HTTPError, ValueError) as exc:
            msg = f"ollama stream failed: {type(exc).__name__}: {exc}"
            raise ProviderError(msg) from exc
