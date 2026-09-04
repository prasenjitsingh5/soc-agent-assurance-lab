"""OpenAI, Azure OpenAI, xAI Grok and any OpenAI-compatible endpoint.

The SDK is imported lazily so the package works without it. A client can be
injected for tests; the contract tests use a stub whose ``create`` returns a
``ChatCompletion`` built from a recorded, sanitized fixture.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

from soclab.contracts import FinishReason, ProviderCapabilities, TokenUsage
from soclab.providers._shared import (
    Timer,
    build_response,
    openai_style_messages,
    openai_style_tools,
    parse_tool_arguments,
)
from soclab.providers.base import (
    CapabilityUnsupportedError,
    MalformedResponseError,
    ModelRequest,
    ModelResponse,
    ProviderError,
    ToolCall,
    estimate_tokens,
)

ADAPTER_VERSION = "1.0.0"

_FINISH = {
    "stop": FinishReason.STOP,
    "tool_calls": FinishReason.TOOL_PROPOSAL,
    "function_call": FinishReason.TOOL_PROPOSAL,
    "length": FinishReason.LENGTH,
    "content_filter": FinishReason.CONTENT_FILTER,
}


def _sdk() -> Any:
    try:
        import openai
    except ImportError as exc:  # pragma: no cover
        msg = "install the 'providers' extra to use the OpenAI adapter"
        raise ProviderError(msg) from exc
    return openai


class OpenAIProvider:
    """Chat Completions adapter. ``provider_id`` distinguishes OpenAI, Azure, xAI and compatible endpoints."""

    def __init__(
        self,
        *,
        model: str,
        provider_id: str = "openai",
        api_key: str | None = None,
        base_url: str | None = None,
        azure_endpoint: str | None = None,
        azure_api_version: str = "2024-10-21",
        client: Any = None,
        timeout_seconds: float = 60.0,
    ) -> None:
        self.provider_id = provider_id
        self.model = model
        if client is not None:
            self._client = client
        elif provider_id == "azure_openai":
            if not azure_endpoint:
                msg = "azure_openai requires azure_endpoint"
                raise ProviderError(msg)
            self._client = _sdk().AsyncAzureOpenAI(
                api_key=api_key,
                azure_endpoint=azure_endpoint,
                api_version=azure_api_version,
                timeout=timeout_seconds,
            )
        else:
            self._client = _sdk().AsyncOpenAI(api_key=api_key, base_url=base_url, timeout=timeout_seconds)

    # ----------------------------------------------------------- capabilities
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

    # ----------------------------------------------------------- calls
    def _params(self, request: ModelRequest, *, structured: bool, with_tools: bool) -> dict[str, Any]:
        params: dict[str, Any] = {
            "model": self.model,
            "messages": openai_style_messages(request),
            "max_completion_tokens": request.max_output_tokens,
            "temperature": request.temperature,
        }
        if with_tools and request.tools:
            params["tools"] = openai_style_tools(request.tools)
            params["tool_choice"] = "auto"
        if structured:
            params["response_format"] = {"type": "json_object"}
        return params

    async def _call(self, params: dict[str, Any]) -> Any:
        try:
            return await self._client.chat.completions.create(**params)
        except Exception as exc:  # noqa: BLE001 - every SDK error becomes a typed ProviderError
            if isinstance(exc, ProviderError):
                raise
            msg = f"{self.provider_id} request failed: {type(exc).__name__}: {exc}"
            raise ProviderError(msg) from exc

    def _normalize(self, completion: Any, *, want_structured: bool, latency_ms: int) -> ModelResponse:
        try:
            choice = completion.choices[0]
        except (AttributeError, IndexError) as exc:
            msg = "completion has no choices"
            raise MalformedResponseError(msg) from exc
        message = choice.message
        tool_call: ToolCall | None = None
        calls = getattr(message, "tool_calls", None) or []
        if calls:
            fn = calls[0].function
            tool_call = ToolCall(name=fn.name, arguments=parse_tool_arguments(fn.arguments))
        finish = _FINISH.get(str(choice.finish_reason), FinishReason.ERROR)
        if tool_call is not None:
            finish = FinishReason.TOOL_PROPOSAL
        usage_obj = getattr(completion, "usage", None)
        usage = (
            TokenUsage(
                input_tokens=usage_obj.prompt_tokens,
                output_tokens=usage_obj.completion_tokens,
                estimated=False,
            )
            if usage_obj is not None
            else TokenUsage(
                input_tokens=0, output_tokens=estimate_tokens(message.content or ""), estimated=True
            )
        )
        return build_response(
            provider=self.provider_id,
            model=getattr(completion, "model", None) or self.model,
            finish=finish,
            text=message.content or "",
            tool_call=tool_call,
            usage=usage,
            latency_ms=latency_ms,
            want_structured=want_structured,
        )

    async def generate(self, request: ModelRequest) -> ModelResponse:
        with Timer() as t:
            completion = await self._call(self._params(request, structured=False, with_tools=False))
        return self._normalize(completion, want_structured=False, latency_ms=t.elapsed_ms)

    async def generate_structured(self, request: ModelRequest) -> ModelResponse:
        with Timer() as t:
            completion = await self._call(
                self._params(request, structured=True, with_tools=bool(request.tools))
            )
        return self._normalize(completion, want_structured=True, latency_ms=t.elapsed_ms)

    async def request_tool(self, request: ModelRequest) -> ModelResponse:
        with Timer() as t:
            completion = await self._call(self._params(request, structured=False, with_tools=True))
        return self._normalize(completion, want_structured=False, latency_ms=t.elapsed_ms)

    async def continue_after_tool(
        self, request: ModelRequest, tool_name: str, tool_result: str
    ) -> ModelResponse:
        from soclab.contracts import TrustLabel
        from soclab.providers.base import Message

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
        params["stream"] = True
        try:
            async for chunk in await self._client.chat.completions.create(**params):
                delta = chunk.choices[0].delta.content if chunk.choices else None
                if delta:
                    yield delta
        except CapabilityUnsupportedError:
            raise
        except Exception as exc:  # noqa: BLE001
            msg = f"{self.provider_id} stream failed: {type(exc).__name__}: {exc}"
            raise ProviderError(msg) from exc
