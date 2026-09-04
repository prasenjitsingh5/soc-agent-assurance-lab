"""Provider registry and capability discovery.

The registry is the single place that knows how to build a provider from
configuration. It reports a :class:`CompatibilityResult` for every known
provider id, including ones whose credentials are absent, so a comparison
report can say "not configured" instead of silently skipping a column.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Mapping
from typing import Any

from soclab.contracts import CompatibilityResult, ProviderCapabilities
from soclab.providers import anthropic_adapter, google_adapter, ollama_adapter, openai_adapter
from soclab.providers.base import ModelProvider, ProviderError
from soclab.providers.mock import MockProvider

Factory = Callable[[Mapping[str, str], str], ModelProvider]


class ProviderEntry:
    def __init__(
        self,
        *,
        provider_id: str,
        adapter_version: str,
        capabilities: ProviderCapabilities,
        required_env: tuple[str, ...],
        default_model: str,
        factory: Factory,
        tested: str,
        region_env: str | None = None,
    ) -> None:
        self.provider_id = provider_id
        self.adapter_version = adapter_version
        self.capabilities = capabilities
        self.required_env = required_env
        self.default_model = default_model
        self.factory = factory
        self.tested = tested
        self.region_env = region_env


_FULL = ProviderCapabilities(
    tool_calling=True, structured_output=True, streaming=True, usage_reporting=True, multimodal_input=True
)


def _openai(env: Mapping[str, str], model: str) -> ModelProvider:
    return openai_adapter.OpenAIProvider(model=model, provider_id="openai", api_key=env.get("OPENAI_API_KEY"))


def _azure(env: Mapping[str, str], model: str) -> ModelProvider:
    return openai_adapter.OpenAIProvider(
        model=model,
        provider_id="azure_openai",
        api_key=env.get("AZURE_OPENAI_API_KEY"),
        azure_endpoint=env.get("AZURE_OPENAI_ENDPOINT"),
        azure_api_version=env.get("AZURE_OPENAI_API_VERSION", "2024-10-21"),
    )


def _xai(env: Mapping[str, str], model: str) -> ModelProvider:
    return openai_adapter.OpenAIProvider(
        model=model, provider_id="xai", api_key=env.get("XAI_API_KEY"), base_url="https://api.x.ai/v1"
    )


def _compatible(env: Mapping[str, str], model: str) -> ModelProvider:
    return openai_adapter.OpenAIProvider(
        model=model,
        provider_id="openai_compatible",
        api_key=env.get("OPENAI_COMPATIBLE_API_KEY", "not-needed"),
        base_url=env.get("OPENAI_COMPATIBLE_BASE_URL"),
    )


def _anthropic(env: Mapping[str, str], model: str) -> ModelProvider:
    return anthropic_adapter.AnthropicProvider(model=model, api_key=env.get("ANTHROPIC_API_KEY"))


def _gemini(env: Mapping[str, str], model: str) -> ModelProvider:
    return google_adapter.GoogleProvider(model=model, provider_id="gemini", api_key=env.get("GOOGLE_API_KEY"))


def _vertex(env: Mapping[str, str], model: str) -> ModelProvider:
    return google_adapter.GoogleProvider(
        model=model,
        provider_id="vertex",
        project=env.get("GOOGLE_CLOUD_PROJECT"),
        location=env.get("GOOGLE_CLOUD_LOCATION"),
    )


def _ollama(env: Mapping[str, str], model: str) -> ModelProvider:
    return ollama_adapter.OllamaProvider(
        model=model, base_url=env.get("OLLAMA_BASE_URL", "http://localhost:11434")
    )


def _mock(env: Mapping[str, str], model: str) -> ModelProvider:
    return MockProvider(model=model)


ENTRIES: dict[str, ProviderEntry] = {
    e.provider_id: e
    for e in (
        ProviderEntry(
            provider_id="mock",
            adapter_version="1.0.0",
            capabilities=ProviderCapabilities(
                tool_calling=True, structured_output=True, streaming=False, usage_reporting=True
            ),
            required_env=(),
            default_model="mock-investigator-v1",
            factory=_mock,
            tested="deterministic, runs in CI",
        ),
        ProviderEntry(
            provider_id="openai",
            adapter_version=openai_adapter.ADAPTER_VERSION,
            capabilities=_FULL,
            required_env=("OPENAI_API_KEY",),
            default_model="gpt-4o-mini",
            factory=_openai,
            tested="contract tests against recorded fixtures",
        ),
        ProviderEntry(
            provider_id="azure_openai",
            adapter_version=openai_adapter.ADAPTER_VERSION,
            capabilities=_FULL,
            required_env=("AZURE_OPENAI_API_KEY", "AZURE_OPENAI_ENDPOINT"),
            default_model="gpt-4o-mini",
            factory=_azure,
            tested="contract tests against recorded fixtures",
            region_env="AZURE_OPENAI_ENDPOINT",
        ),
        ProviderEntry(
            provider_id="anthropic",
            adapter_version=anthropic_adapter.ADAPTER_VERSION,
            capabilities=_FULL,
            required_env=("ANTHROPIC_API_KEY",),
            default_model="claude-sonnet-4-20250514",
            factory=_anthropic,
            tested="contract tests against recorded fixtures",
        ),
        ProviderEntry(
            provider_id="gemini",
            adapter_version=google_adapter.ADAPTER_VERSION,
            capabilities=_FULL,
            required_env=("GOOGLE_API_KEY",),
            default_model="gemini-2.5-flash",
            factory=_gemini,
            tested="contract tests against recorded fixtures",
        ),
        ProviderEntry(
            provider_id="vertex",
            adapter_version=google_adapter.ADAPTER_VERSION,
            capabilities=_FULL,
            required_env=("GOOGLE_CLOUD_PROJECT", "GOOGLE_CLOUD_LOCATION"),
            default_model="gemini-2.5-flash",
            factory=_vertex,
            tested="contract tests against recorded fixtures",
            region_env="GOOGLE_CLOUD_LOCATION",
        ),
        ProviderEntry(
            provider_id="xai",
            adapter_version=openai_adapter.ADAPTER_VERSION,
            capabilities=ProviderCapabilities(
                tool_calling=True, structured_output=True, streaming=True, usage_reporting=True
            ),
            required_env=("XAI_API_KEY",),
            default_model="grok-4",
            factory=_xai,
            tested="contract tests against recorded fixtures via the OpenAI-compatible adapter",
        ),
        ProviderEntry(
            provider_id="ollama",
            adapter_version=ollama_adapter.ADAPTER_VERSION,
            capabilities=ProviderCapabilities(
                tool_calling=True, structured_output=True, streaming=True, usage_reporting=True
            ),
            required_env=(),
            default_model="llama3.1",
            factory=_ollama,
            tested="contract tests against recorded fixtures",
        ),
        ProviderEntry(
            provider_id="openai_compatible",
            adapter_version=openai_adapter.ADAPTER_VERSION,
            capabilities=ProviderCapabilities(
                tool_calling=True, structured_output=True, streaming=True, usage_reporting=False
            ),
            required_env=("OPENAI_COMPATIBLE_BASE_URL",),
            default_model="default",
            factory=_compatible,
            tested="gateway path for LiteLLM, vLLM and OpenRouter; fixture tested via the OpenAI adapter",
        ),
    )
}


class ProviderRegistry:
    def __init__(
        self, env: Mapping[str, str] | None = None, *, approved: tuple[str, ...] | None = None
    ) -> None:
        self._env = dict(env if env is not None else os.environ)
        self._approved = set(approved) if approved is not None else set(ENTRIES)

    def ids(self) -> tuple[str, ...]:
        return tuple(ENTRIES)

    def entry(self, provider_id: str) -> ProviderEntry:
        try:
            return ENTRIES[provider_id]
        except KeyError as exc:
            msg = f"unknown provider {provider_id!r}; known: {', '.join(ENTRIES)}"
            raise ProviderError(msg) from exc

    def configured(self, provider_id: str) -> bool:
        return all(self._env.get(name) for name in self.entry(provider_id).required_env)

    def compatibility(self, provider_id: str) -> CompatibilityResult:
        entry = self.entry(provider_id)
        limitations: list[str] = []
        missing = [name for name in entry.required_env if not self._env.get(name)]
        if missing:
            limitations.append(f"credentials not configured: {', '.join(missing)}")
        if not entry.capabilities.streaming:
            limitations.append("streaming not supported")
        if not entry.capabilities.usage_reporting:
            limitations.append("usage is estimated, not provider reported")
        if provider_id not in self._approved:
            limitations.append("not on the approved provider list")
        limitations.append(f"validation: {entry.tested}")
        return CompatibilityResult(
            provider_id=provider_id,
            adapter_version=entry.adapter_version,
            approved=provider_id in self._approved,
            capabilities=entry.capabilities,
            region=self._env.get(entry.region_env) if entry.region_env else None,
            limitations=tuple(limitations),
        )

    def get(self, provider_id: str, *, model: str | None = None) -> ModelProvider:
        entry = self.entry(provider_id)
        if provider_id not in self._approved:
            msg = f"provider {provider_id!r} is not on the approved list"
            raise ProviderError(msg)
        if not self.configured(provider_id):
            msg = f"provider {provider_id!r} is not configured; set {', '.join(entry.required_env)}"
            raise ProviderError(msg)
        return entry.factory(self._env, model or entry.default_model)

    def matrix(self) -> list[dict[str, Any]]:
        return [self.compatibility(pid).model_dump(mode="json") for pid in ENTRIES]
