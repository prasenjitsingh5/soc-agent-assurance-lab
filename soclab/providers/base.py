"""Canonical model interface and request/response contracts."""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any, Protocol, runtime_checkable

from pydantic import Field

from soclab.contracts import FinishReason, ProviderCapabilities, StrictModel, TokenUsage, TrustLabel


class ProviderError(Exception):
    """Transport, authentication or provider-side failure. Never retried blindly."""


class MalformedResponseError(ProviderError):
    """The provider returned something that does not satisfy the requested schema."""


class CapabilityUnsupportedError(ProviderError):
    """The caller asked for a capability the adapter explicitly does not offer."""


class Message(StrictModel):
    role: str = Field(pattern=r"^(system|user|assistant|tool)$")
    content: str
    trust: TrustLabel = TrustLabel.TRUSTED
    tool_name: str | None = None


class ToolSpec(StrictModel):
    name: str = Field(pattern=r"^[a-z][a-z0-9_]*$")
    description: str = Field(min_length=1)
    parameters: dict[str, Any]


class ToolCall(StrictModel):
    name: str = Field(pattern=r"^[a-z][a-z0-9_]*$")
    arguments: dict[str, Any]


class ModelRequest(StrictModel):
    """Everything a provider needs for one turn. Stage names let deterministic providers script replies.

    The orchestrator sets the run, trace and incident identifiers so an adapter that
    talks to an external agent can correlate turns. Vendor adapters ignore them.
    """

    stage: str = Field(pattern=r"^[a-z][a-z0-9_]*$")
    system_prompt: str
    messages: tuple[Message, ...]
    tools: tuple[ToolSpec, ...] = ()
    response_schema: dict[str, Any] | None = None
    max_output_tokens: int = Field(default=1024, ge=1)
    temperature: float = Field(default=0.0, ge=0.0, le=2.0)
    run_id: str | None = None
    trace_id: str | None = None
    incident_id: str | None = None


class ModelResponse(StrictModel):
    """Normalized provider reply. Exactly one of structured or tool_call is set for a successful turn."""

    provider: str
    model: str
    finish_reason: FinishReason
    output_text: str = ""
    structured: dict[str, Any] | None = None
    tool_call: ToolCall | None = None
    usage: TokenUsage
    latency_ms: int = Field(ge=0)
    estimated_cost_usd: float | None = Field(default=None, ge=0)
    cost_is_estimated: bool = True


@runtime_checkable
class ModelProvider(Protocol):
    """The seven operations every adapter implements. Unsupported ones raise CapabilityUnsupportedError."""

    provider_id: str
    model: str

    def describe_capabilities(self) -> ProviderCapabilities: ...

    async def generate(self, request: ModelRequest) -> ModelResponse: ...

    async def generate_structured(self, request: ModelRequest) -> ModelResponse: ...

    async def request_tool(self, request: ModelRequest) -> ModelResponse: ...

    async def continue_after_tool(
        self, request: ModelRequest, tool_name: str, tool_result: str
    ) -> ModelResponse: ...

    def stream(self, request: ModelRequest) -> AsyncIterator[str]: ...

    def count_usage(self, request: ModelRequest) -> TokenUsage: ...


def estimate_tokens(text: str) -> int:
    """Crude, provider-independent estimate. Always labeled as estimated where it is used."""
    return max(1, len(text) // 4)
