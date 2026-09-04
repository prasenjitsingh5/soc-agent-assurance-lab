"""Google Gemini (AI Studio) and Vertex AI through the google-genai SDK.

Both are the same adapter with different client construction. ``provider_id``
is ``gemini`` for API-key access and ``vertex`` for project and location access.
"""

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

_FINISH = {
    "STOP": FinishReason.STOP,
    "MAX_TOKENS": FinishReason.LENGTH,
    "SAFETY": FinishReason.CONTENT_FILTER,
    "RECITATION": FinishReason.CONTENT_FILTER,
    "PROHIBITED_CONTENT": FinishReason.CONTENT_FILTER,
}


def _sdk() -> Any:
    try:
        from google import genai
    except ImportError as exc:  # pragma: no cover
        msg = "install the 'providers' extra to use the Google adapter"
        raise ProviderError(msg) from exc
    return genai


class GoogleProvider:
    def __init__(
        self,
        *,
        model: str,
        provider_id: str = "gemini",
        api_key: str | None = None,
        project: str | None = None,
        location: str | None = None,
        client: Any = None,
    ) -> None:
        self.provider_id = provider_id
        self.model = model
        if client is not None:
            self._client = client
        elif provider_id == "vertex":
            if not project or not location:
                msg = "vertex requires project and location"
                raise ProviderError(msg)
            self._client = _sdk().Client(vertexai=True, project=project, location=location)
        else:
            self._client = _sdk().Client(api_key=api_key)

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
    def _contents(request: ModelRequest) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for m in request.messages:
            role = "model" if m.role == "assistant" else "user"
            prefix = (
                f"[tool:{m.tool_name} trust={m.trust.value}] "
                if m.role == "tool"
                else f"[trust={m.trust.value}] "
            )
            text = m.content if role == "model" else prefix + m.content
            out.append({"role": role, "parts": [{"text": text}]})
        return out or [{"role": "user", "parts": [{"text": "Begin."}]}]

    def _config(self, request: ModelRequest, *, structured: bool, with_tools: bool) -> dict[str, Any]:
        config: dict[str, Any] = {
            "system_instruction": request.system_prompt,
            "max_output_tokens": request.max_output_tokens,
            "temperature": request.temperature,
        }
        if structured and not (with_tools and request.tools):
            config["response_mime_type"] = "application/json"
        if with_tools and request.tools:
            config["tools"] = [
                {
                    "function_declarations": [
                        {"name": t.name, "description": t.description, "parameters": t.parameters}
                        for t in request.tools
                    ]
                }
            ]
        return config

    async def _call(self, request: ModelRequest, *, structured: bool, with_tools: bool) -> Any:
        try:
            return await self._client.aio.models.generate_content(
                model=self.model,
                contents=self._contents(request),
                config=self._config(request, structured=structured, with_tools=with_tools),
            )
        except Exception as exc:  # noqa: BLE001
            if isinstance(exc, ProviderError):
                raise
            msg = f"{self.provider_id} request failed: {type(exc).__name__}: {exc}"
            raise ProviderError(msg) from exc

    def _normalize(self, response: Any, *, want_structured: bool, latency_ms: int) -> ModelResponse:
        candidates = getattr(response, "candidates", None) or []
        if not candidates:
            msg = "response has no candidates"
            raise MalformedResponseError(msg)
        candidate = candidates[0]
        parts = getattr(getattr(candidate, "content", None), "parts", None) or []
        text_parts: list[str] = []
        tool_call: ToolCall | None = None
        for part in parts:
            fc = getattr(part, "function_call", None)
            if fc is not None and tool_call is None:
                tool_call = ToolCall(name=fc.name, arguments=dict(fc.args or {}))
            elif getattr(part, "text", None):
                text_parts.append(part.text)
        finish_raw = getattr(candidate, "finish_reason", None)
        finish = _FINISH.get(str(getattr(finish_raw, "name", finish_raw) or ""), FinishReason.ERROR)
        if tool_call is not None:
            finish = FinishReason.TOOL_PROPOSAL
        meta = getattr(response, "usage_metadata", None)
        usage = (
            TokenUsage(
                input_tokens=int(meta.prompt_token_count or 0),
                output_tokens=int(meta.candidates_token_count or 0),
                estimated=False,
            )
            if meta is not None
            else TokenUsage(
                input_tokens=0, output_tokens=estimate_tokens("".join(text_parts)), estimated=True
            )
        )
        return build_response(
            provider=self.provider_id,
            model=self.model,
            finish=finish,
            text="".join(text_parts),
            tool_call=tool_call,
            usage=usage,
            latency_ms=latency_ms,
            want_structured=want_structured,
        )

    async def generate(self, request: ModelRequest) -> ModelResponse:
        with Timer() as t:
            response = await self._call(request, structured=False, with_tools=False)
        return self._normalize(response, want_structured=False, latency_ms=t.elapsed_ms)

    async def generate_structured(self, request: ModelRequest) -> ModelResponse:
        with Timer() as t:
            response = await self._call(request, structured=True, with_tools=bool(request.tools))
        return self._normalize(response, want_structured=True, latency_ms=t.elapsed_ms)

    async def request_tool(self, request: ModelRequest) -> ModelResponse:
        with Timer() as t:
            response = await self._call(request, structured=False, with_tools=True)
        return self._normalize(response, want_structured=False, latency_ms=t.elapsed_ms)

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
        try:
            stream = await self._client.aio.models.generate_content_stream(
                model=self.model,
                contents=self._contents(request),
                config=self._config(request, structured=False, with_tools=False),
            )
            async for chunk in stream:
                if getattr(chunk, "text", None):
                    yield chunk.text
        except Exception as exc:  # noqa: BLE001
            msg = f"{self.provider_id} stream failed: {type(exc).__name__}: {exc}"
            raise ProviderError(msg) from exc
