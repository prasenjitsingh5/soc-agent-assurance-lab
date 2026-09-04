"""Helpers shared by the adapters. Nothing here imports a vendor SDK."""

from __future__ import annotations

import json
import time
from typing import Any

from soclab.contracts import FinishReason, TokenUsage
from soclab.providers.base import (
    MalformedResponseError,
    Message,
    ModelRequest,
    ModelResponse,
    ToolCall,
    ToolSpec,
)

# Estimated list prices in USD per million tokens (input, output). Marked estimated everywhere they are used.
# Values are placeholders for cost comparison; check the vendor price list before quoting them.
PRICE_TABLE_USD_PER_MTOK: dict[str, tuple[float, float]] = {
    "gpt-4o": (2.50, 10.00),
    "gpt-4o-mini": (0.15, 0.60),
    "claude-sonnet-4-20250514": (3.00, 15.00),
    "claude-haiku-4-5-20251001": (1.00, 5.00),
    "gemini-2.5-pro": (1.25, 10.00),
    "gemini-2.5-flash": (0.30, 2.50),
    "grok-4": (3.00, 15.00),
}


def estimate_cost_usd(model: str, usage: TokenUsage) -> float | None:
    prices = PRICE_TABLE_USD_PER_MTOK.get(model)
    if prices is None:
        return None
    return round((usage.input_tokens * prices[0] + usage.output_tokens * prices[1]) / 1_000_000, 6)


class Timer:
    def __enter__(self) -> Timer:
        self._start = time.perf_counter()
        return self

    def __exit__(self, *_: object) -> None:
        self.elapsed_ms = int((time.perf_counter() - self._start) * 1000)


def parse_structured(text: str) -> dict[str, Any]:
    """Parse the model's text as a JSON object. Anything else is malformed."""
    candidate = text.strip()
    if candidate.startswith("```"):
        candidate = candidate.strip("`")
        if candidate.startswith("json"):
            candidate = candidate[4:]
    try:
        value = json.loads(candidate)
    except json.JSONDecodeError as exc:
        msg = f"provider returned non-JSON text: {text[:120]!r}"
        raise MalformedResponseError(msg) from exc
    if not isinstance(value, dict):
        msg = f"provider returned JSON that is not an object: {type(value).__name__}"
        raise MalformedResponseError(msg)
    return value


def parse_tool_arguments(raw: Any) -> dict[str, Any]:
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        try:
            value = json.loads(raw or "{}")
        except json.JSONDecodeError as exc:
            msg = f"tool arguments are not valid JSON: {raw[:120]!r}"
            raise MalformedResponseError(msg) from exc
        if isinstance(value, dict):
            return value
    msg = "tool arguments must be a JSON object"
    raise MalformedResponseError(msg)


def openai_style_messages(request: ModelRequest) -> list[dict[str, Any]]:
    """System prompt plus messages in the shape OpenAI-compatible APIs accept."""
    out: list[dict[str, Any]] = [{"role": "system", "content": request.system_prompt}]
    for m in request.messages:
        out.append(_flatten(m))
    return out


def _flatten(m: Message) -> dict[str, Any]:
    # Tool results are presented as user-role content labeled by origin. Trust labels are preserved
    # in the text so downstream logging can show where untrusted data entered the context.
    if m.role == "tool":
        return {"role": "user", "content": f"[tool:{m.tool_name} trust={m.trust.value}] {m.content}"}
    if m.role == "assistant":
        return {"role": "assistant", "content": m.content}
    return {"role": "user", "content": f"[trust={m.trust.value}] {m.content}"}


def openai_style_tools(tools: tuple[ToolSpec, ...]) -> list[dict[str, Any]]:
    return [
        {
            "type": "function",
            "function": {"name": t.name, "description": t.description, "parameters": t.parameters},
        }
        for t in tools
    ]


def build_response(
    *,
    provider: str,
    model: str,
    finish: FinishReason,
    text: str,
    tool_call: ToolCall | None,
    usage: TokenUsage,
    latency_ms: int,
    want_structured: bool,
) -> ModelResponse:
    structured = None
    if tool_call is None and want_structured and finish is not FinishReason.ERROR:
        structured = parse_structured(text)
    return ModelResponse(
        provider=provider,
        model=model,
        finish_reason=finish,
        output_text=text,
        structured=structured,
        tool_call=tool_call,
        usage=usage,
        latency_ms=latency_ms,
        estimated_cost_usd=estimate_cost_usd(model, usage),
        cost_is_estimated=True,
    )
