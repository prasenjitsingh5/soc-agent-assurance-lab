"""Provider adapter contract tests. No network. Every vendor response is a recorded, sanitized fixture."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest

from soclab.contracts import FinishReason, TrustLabel
from soclab.providers import (
    CapabilityUnsupportedError,
    MalformedResponseError,
    Message,
    ModelProvider,
    ModelRequest,
    ProviderError,
    ToolSpec,
)
from soclab.providers.anthropic_adapter import AnthropicProvider
from soclab.providers.google_adapter import GoogleProvider
from soclab.providers.mock import MockProvider
from soclab.providers.ollama_adapter import OllamaProvider
from soclab.providers.openai_adapter import OpenAIProvider
from soclab.providers.registry import ENTRIES, ProviderRegistry

FIXTURES = Path(__file__).parent / "fixtures"
PROVIDER_IDS = [
    "mock",
    "openai",
    "azure_openai",
    "anthropic",
    "gemini",
    "vertex",
    "xai",
    "ollama",
    "openai_compatible",
]


def fixture(name: str) -> dict[str, Any]:
    with (FIXTURES / f"{name}.json").open(encoding="utf-8") as handle:
        data: dict[str, Any] = json.load(handle)
        return data


def request() -> ModelRequest:
    return ModelRequest(
        stage="collect_identity",
        system_prompt="You are a SOC investigator.",
        messages=(
            Message(role="user", content='{"alert": "impossible travel"}', trust=TrustLabel.UNTRUSTED),
            Message(
                role="tool",
                tool_name="search_siem_events",
                content='{"events": []}',
                trust=TrustLabel.UNTRUSTED,
            ),
        ),
        tools=(ToolSpec(name="get_identity_profile", description="d", parameters={"type": "object"}),),
        response_schema={"type": "object"},
    )


# ----------------------------------------------------------------- registry
@pytest.fixture
def registry() -> ProviderRegistry:
    return ProviderRegistry(env={"OPENAI_API_KEY": "sk-test", "OLLAMA_BASE_URL": "http://localhost:11434"})


@pytest.mark.parametrize("provider_id", PROVIDER_IDS)
def test_provider_declares_capabilities(registry: ProviderRegistry, provider_id: str) -> None:
    result = registry.compatibility(provider_id)
    assert result.provider_id == provider_id
    assert result.capabilities.structured_output in {True, False}
    assert result.adapter_version
    assert any(item.startswith("validation:") for item in result.limitations)


def test_unconfigured_provider_is_explicit_not_silent(registry: ProviderRegistry) -> None:
    result = registry.compatibility("anthropic")
    assert result.approved is True
    assert any("credentials not configured: ANTHROPIC_API_KEY" in item for item in result.limitations)
    with pytest.raises(ProviderError, match="not configured"):
        registry.get("anthropic")


def test_unapproved_provider_is_blocked() -> None:
    registry = ProviderRegistry(env={"OPENAI_API_KEY": "sk-test"}, approved=("mock",))
    assert registry.compatibility("openai").approved is False
    with pytest.raises(ProviderError, match="not on the approved list"):
        registry.get("openai")
    assert isinstance(registry.get("mock"), MockProvider)


def test_unknown_provider_rejected(registry: ProviderRegistry) -> None:
    with pytest.raises(ProviderError, match="unknown provider"):
        registry.compatibility("bedrock-direct")


def test_registry_builds_configured_providers(registry: ProviderRegistry) -> None:
    provider = registry.get("openai")
    assert isinstance(provider, OpenAIProvider)
    assert provider.model == ENTRIES["openai"].default_model
    assert isinstance(registry.get("ollama", model="phi3"), OllamaProvider)
    matrix = registry.matrix()
    assert {row["provider_id"] for row in matrix} == set(PROVIDER_IDS)


def test_every_registered_provider_satisfies_the_protocol() -> None:
    env = {
        "OPENAI_API_KEY": "sk-test",
        "AZURE_OPENAI_API_KEY": "az-test",
        "AZURE_OPENAI_ENDPOINT": "https://example.openai.azure.com",
        "ANTHROPIC_API_KEY": "sk-ant-test",
        "GOOGLE_API_KEY": "g-test",
        "GOOGLE_CLOUD_PROJECT": "proj",
        "GOOGLE_CLOUD_LOCATION": "us-central1",
        "XAI_API_KEY": "xai-test",
        "OPENAI_COMPATIBLE_BASE_URL": "http://localhost:4000/v1",
    }
    registry = ProviderRegistry(env=env)
    for provider_id in PROVIDER_IDS:
        provider = registry.get(provider_id)
        assert isinstance(provider, ModelProvider), provider_id
        assert provider.provider_id == provider_id


# ----------------------------------------------------------------- OpenAI family
class _OpenAIStub:
    def __init__(self, payload: dict[str, Any] | Exception) -> None:
        from openai.types.chat import ChatCompletion

        self._payload = payload
        self.calls: list[dict[str, Any]] = []
        self.chat = self
        self.completions = self
        self._model = ChatCompletion

    async def create(self, **params: Any) -> Any:
        self.calls.append(params)
        if isinstance(self._payload, Exception):
            raise self._payload
        return self._model.model_validate(self._payload)


async def test_openai_structured_output() -> None:
    stub = _OpenAIStub(fixture("openai_structured"))
    provider = OpenAIProvider(model="gpt-4o-mini", client=stub)
    response = await provider.generate_structured(request())
    assert response.structured == {"tool": "get_identity_profile", "arguments": {"user_id": "u-alex-rivera"}}
    assert response.finish_reason is FinishReason.STOP
    assert response.usage.input_tokens == 412 and response.usage.estimated is False
    assert response.estimated_cost_usd is not None and response.cost_is_estimated is True
    sent = stub.calls[0]
    assert sent["response_format"] == {"type": "json_object"}
    assert sent["messages"][0]["role"] == "system"
    assert "trust=untrusted" in sent["messages"][2]["content"]


async def test_openai_tool_proposal_is_normalized() -> None:
    provider = OpenAIProvider(model="gpt-4o-mini", client=_OpenAIStub(fixture("openai_tool_call")))
    response = await provider.request_tool(request())
    assert response.finish_reason is FinishReason.TOOL_PROPOSAL
    assert response.tool_call is not None
    assert response.tool_call.name == "lookup_indicator"
    assert response.tool_call.arguments == {"indicator": "198.51.100.77"}


async def test_openai_malformed_and_truncated() -> None:
    provider = OpenAIProvider(model="gpt-4o-mini", client=_OpenAIStub(fixture("openai_malformed")))
    with pytest.raises(MalformedResponseError, match="non-JSON"):
        await provider.generate_structured(request())
    plain = await OpenAIProvider(
        model="gpt-4o-mini", client=_OpenAIStub(fixture("openai_malformed"))
    ).generate(request())
    assert plain.structured is None and plain.output_text.startswith("Sure!")
    truncated = OpenAIProvider(model="gpt-4o-mini", client=_OpenAIStub(fixture("openai_length")))
    with pytest.raises(MalformedResponseError):
        await truncated.generate_structured(request())


async def test_openai_provider_error_is_typed() -> None:
    import openai

    err = openai.APIConnectionError(
        request=httpx.Request("POST", "https://api.openai.com/v1/chat/completions")
    )
    provider = OpenAIProvider(model="gpt-4o-mini", client=_OpenAIStub(err))
    with pytest.raises(ProviderError, match="APIConnectionError"):
        await provider.generate_structured(request())


def test_azure_and_xai_are_configurations_of_the_openai_adapter() -> None:
    azure = OpenAIProvider(
        model="gpt-4o-mini",
        provider_id="azure_openai",
        api_key="k",
        azure_endpoint="https://x.openai.azure.com",
    )
    assert azure.provider_id == "azure_openai"
    with pytest.raises(ProviderError, match="requires azure_endpoint"):
        OpenAIProvider(model="m", provider_id="azure_openai", api_key="k")
    xai = OpenAIProvider(model="grok-4", provider_id="xai", api_key="k", base_url="https://api.x.ai/v1")
    assert xai.provider_id == "xai"


# ----------------------------------------------------------------- Anthropic
class _AnthropicStub:
    def __init__(self, payload: dict[str, Any] | Exception) -> None:
        from anthropic.types import Message as AnthropicMessage

        self._payload = payload
        self._model = AnthropicMessage
        self.calls: list[dict[str, Any]] = []
        self.messages = self

    async def create(self, **params: Any) -> Any:
        self.calls.append(params)
        if isinstance(self._payload, Exception):
            raise self._payload
        return self._model.model_validate(self._payload)


async def test_anthropic_structured_output_and_message_shaping() -> None:
    stub = _AnthropicStub(fixture("anthropic_structured"))
    provider = AnthropicProvider(model="claude-sonnet-4-20250514", client=stub)
    response = await provider.generate_structured(request())
    assert response.structured == {
        "tool": "get_authentication_history",
        "arguments": {"user_id": "u-alex-rivera"},
    }
    assert response.usage.output_tokens == 31 and response.usage.estimated is False
    sent = stub.calls[0]
    assert "single JSON object" in sent["system"]
    assert sent["messages"][0]["role"] == "user"
    assert all(m["role"] in {"user", "assistant"} for m in sent["messages"])


async def test_anthropic_tool_use_block() -> None:
    provider = AnthropicProvider(
        model="claude-sonnet-4-20250514", client=_AnthropicStub(fixture("anthropic_tool_use"))
    )
    response = await provider.request_tool(request())
    assert response.finish_reason is FinishReason.TOOL_PROPOSAL
    assert response.tool_call is not None and response.tool_call.name == "get_endpoint_status"
    assert response.output_text == "Checking the endpoint."


async def test_anthropic_malformed_and_errors() -> None:
    provider = AnthropicProvider(model="m", client=_AnthropicStub(fixture("anthropic_malformed")))
    with pytest.raises(MalformedResponseError):
        await provider.generate_structured(request())
    failing = AnthropicProvider(model="m", client=_AnthropicStub(RuntimeError("socket closed")))
    with pytest.raises(ProviderError, match="RuntimeError"):
        await failing.generate(request())


# ----------------------------------------------------------------- Google
class _GoogleStub:
    def __init__(self, payload: dict[str, Any] | Exception) -> None:
        from google.genai import types

        self._payload = payload
        self._model = types.GenerateContentResponse
        self.calls: list[dict[str, Any]] = []
        self.aio = self
        self.models = self

    async def generate_content(self, **params: Any) -> Any:
        self.calls.append(params)
        if isinstance(self._payload, Exception):
            raise self._payload
        return self._model.model_validate(self._payload)


async def test_gemini_structured_output() -> None:
    stub = _GoogleStub(fixture("gemini_structured"))
    provider = GoogleProvider(model="gemini-2.5-flash", client=stub)
    response = await provider.generate_structured(request().model_copy(update={"tools": ()}))
    assert response.structured == {"tool": "search_siem_events", "arguments": {"query": "u-alex-rivera"}}
    assert response.usage.input_tokens == 401
    assert stub.calls[0]["config"]["response_mime_type"] == "application/json"


async def test_gemini_function_call_and_safety_block() -> None:
    provider = GoogleProvider(model="gemini-2.5-flash", client=_GoogleStub(fixture("gemini_function_call")))
    response = await provider.request_tool(request())
    assert response.tool_call is not None and response.tool_call.arguments == {"indicator": "198.51.100.77"}
    blocked = GoogleProvider(model="gemini-2.5-flash", client=_GoogleStub(fixture("gemini_safety")))
    with pytest.raises(MalformedResponseError):
        await blocked.generate_structured(request())
    plain = await GoogleProvider(
        model="gemini-2.5-flash", client=_GoogleStub(fixture("gemini_safety"))
    ).generate(request())
    assert plain.finish_reason is FinishReason.CONTENT_FILTER


def test_vertex_requires_project_and_location() -> None:
    with pytest.raises(ProviderError, match="project and location"):
        GoogleProvider(model="gemini-2.5-flash", provider_id="vertex")
    provider = GoogleProvider(
        model="gemini-2.5-flash", provider_id="vertex", project="p", location="us-central1", client=object()
    )
    assert provider.provider_id == "vertex"


# ----------------------------------------------------------------- Ollama over HTTP
def _ollama(payload: dict[str, Any] | int) -> OllamaProvider:
    def handler(req: httpx.Request) -> httpx.Response:
        assert req.url.path == "/api/chat"
        if isinstance(payload, int):
            return httpx.Response(payload, text="boom")
        return httpx.Response(200, json=payload)

    return OllamaProvider(model="llama3.1", transport=httpx.MockTransport(handler))


async def test_ollama_structured_tool_and_usage() -> None:
    response = await _ollama(fixture("ollama_structured")).generate_structured(request())
    assert response.structured == {"tool": "get_identity_profile", "arguments": {"user_id": "u-alex-rivera"}}
    assert response.usage.input_tokens == 350 and response.usage.estimated is False
    assert response.estimated_cost_usd == 0.0 and response.cost_is_estimated is True
    tool = await _ollama(fixture("ollama_tool_call")).request_tool(request())
    assert tool.tool_call is not None and tool.tool_call.name == "get_endpoint_status"


async def test_ollama_malformed_and_http_error() -> None:
    with pytest.raises(MalformedResponseError):
        await _ollama(fixture("ollama_malformed")).generate_structured(request())
    with pytest.raises(ProviderError, match="HTTPStatusError"):
        await _ollama(503).generate(request())


# ----------------------------------------------------------------- capability gaps are explicit
def test_mock_stream_is_an_explicit_capability_gap() -> None:
    provider = MockProvider()
    assert provider.describe_capabilities().streaming is False
    with pytest.raises(CapabilityUnsupportedError):
        provider.stream(request())
