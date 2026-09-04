"""Anthropic Messages API adapter."""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

from soclab.contracts import FinishReason, ProviderCapabilities, TokenUsage, TrustLabel
from soclab.providers._shared import Timer, build_response
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

_STOP = {
    "end_turn": FinishReason.STOP,
    "stop_sequence": FinishReason.STOP,
    "tool_use": FinishReason.TOOL_PROPOSAL,
    "max_tokens": FinishReason.LENGTH,
    "refusal": FinishReason.CONTENT_FILTER,
}


def _sdk() -> Any:
    try:
        import anthropic
    except ImportError as exc:  # pragma: no cover
        msg = "install the 'providers' extra to use the Anthropic adapter"
        raise ProviderError(msg) from exc
    return anthropic


class AnthropicProvider:
    provider_id = "anthropic"

    def __init__(
        self, *, model: str, api_key: str | None = None, client: Any = None, timeout_seconds: float = 60.0
    ) -> None:
        self.model = model
        self._client = (
            client if client is not None else _sdk().AsyncAnthropic(api_key=api_key, timeout=timeout_seconds)
        )

    def describe_capabilities(self) -> ProviderCapabilities:
        return ProviderCapabilities(
            tool_calling=True,
            structured_output=True,
            streaming=True,
            usage_reporting=True,
            multimodal_input=True,
        )

    def count_usage(self, request: ModelRequest) -> TokenUsage:
        text = request.system_prompt + "".join(m.content for m in request.messages)
        return TokenUsage(input_tokens=estimate_tokens(text), output_tokens=0, estimated=True)

    @staticmethod
    def _messages(request: ModelRequest) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for m in request.messages:
            role = "assistant" if m.role == "assistant" else "user"
            prefix = (
                f"[tool:{m.tool_name} trust={m.trust.value}] "
                if m.role == "tool"
                else f"[trust={m.trust.value}] "
            )
            content = m.content if role == "assistant" else prefix + m.content
            if out and out[-1]["role"] == role:
                out[-1]["content"] += "\n" + content
            else:
                out.append({"role": role, "content": content})
        if not out or out[0]["role"] != "user":
            out.insert(0, {"role": "user", "content": "Begin."})
        return out

    def _params(self, request: ModelRequest, *, structured: bool, with_tools: bool) -> dict[str, Any]:
        system = request.system_prompt
        if structured:
            system += "\nRespond with a single JSON object and nothing else."
        params: dict[str, Any] = {
            "model": self.model,
            "system": system,
            "messages": self._messages(request),
            "max_tokens": request.max_output_tokens,
            "temperature": request.temperature,
        }
        if with_tools and request.tools:
            params["tools"] = [
                {"name": t.name, "description": t.description, "input_schema": t.parameters}
                for t in request.tools
            ]
        return params

    async def _call(self, params: dict[str, Any]) -> Any:
        try:
            return await self._client.messages.create(**params)
        except Exception as exc:  # noqa: BLE001
            if isinstance(exc, ProviderError):
                raise
            msg = f"anthropic request failed: {type(exc).__name__}: {exc}"
            raise ProviderError(msg) from exc

    def _normalize(self, message: Any, *, want_structured: bool, latency_ms: int) -> ModelResponse:
        blocks = getattr(message, "content", None)
        if not blocks:
            msg = "message has no content blocks"
            raise MalformedResponseError(msg)
        text_parts: list[str] = []
        tool_call: ToolCall | None = None
        for block in blocks:
            kind = getattr(block, "type", None)
            if kind == "text":
                text_parts.append(block.text)
            elif kind == "tool_use" and tool_call is None:
                arguments = block.input if isinstance(block.input, dict) else {}
                tool_call = ToolCall(name=block.name, arguments=arguments)
        finish = _STOP.get(str(getattr(message, "stop_reason", "")), FinishReason.ERROR)
        if tool_call is not None:
            finish = FinishReason.TOOL_PROPOSAL
        usage_obj = getattr(message, "usage", None)
        usage = (
            TokenUsage(
                input_tokens=usage_obj.input_tokens, output_tokens=usage_obj.output_tokens, estimated=False
            )
            if usage_obj is not None
            else TokenUsage(
                input_tokens=0, output_tokens=estimate_tokens("".join(text_parts)), estimated=True
            )
        )
        return build_response(
            provider=self.provider_id,
            model=getattr(message, "model", None) or self.model,
            finish=finish,
            text="".join(text_parts),
            tool_call=tool_call,
            usage=usage,
            latency_ms=latency_ms,
            want_structured=want_structured,
        )

    async def generate(self, request: ModelRequest) -> ModelResponse:
        with Timer() as t:
            message = await self._call(self._params(request, structured=False, with_tools=False))
        return self._normalize(message, want_structured=False, latency_ms=t.elapsed_ms)

    async def generate_structured(self, request: ModelRequest) -> ModelResponse:
        with Timer() as t:
            message = await self._call(self._params(request, structured=True, with_tools=bool(request.tools)))
        return self._normalize(message, want_structured=True, latency_ms=t.elapsed_ms)

    async def request_tool(self, request: ModelRequest) -> ModelResponse:
        with Timer() as t:
            message = await self._call(self._params(request, structured=False, with_tools=True))
        return self._normalize(message, want_structured=False, latency_ms=t.elapsed_ms)

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
        params = self._params(request, structured=False, with_tools=False)
        try:
            async with self._client.messages.stream(**params) as stream:
                async for text in stream.text_stream:
                    yield text
        except Exception as exc:  # noqa: BLE001
            msg = f"anthropic stream failed: {type(exc).__name__}: {exc}"
            raise ProviderError(msg) from exc
