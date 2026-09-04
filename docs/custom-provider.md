# Adding a custom provider

A provider is any object that satisfies `soclab.providers.ModelProvider`. Nothing outside your adapter may see the vendor SDK's types.

## 1. Implement the interface

```python
from collections.abc import AsyncIterator

from soclab.contracts import FinishReason, ProviderCapabilities, TokenUsage
from soclab.providers import CapabilityUnsupportedError, MalformedResponseError, ModelRequest, ModelResponse
from soclab.providers._shared import Timer, build_response, openai_style_messages


class CorporateGatewayProvider:
    provider_id = "corp_gateway"

    def __init__(self, *, model: str, endpoint: str, token: str) -> None:
        self.model = model
        self._endpoint = endpoint
        self._token = token

    def describe_capabilities(self) -> ProviderCapabilities:
        return ProviderCapabilities(
            tool_calling=False, structured_output=True, streaming=False, usage_reporting=False
        )

    def count_usage(self, request: ModelRequest) -> TokenUsage:
        text = request.system_prompt + "".join(m.content for m in request.messages)
        return TokenUsage(input_tokens=len(text) // 4, output_tokens=0, estimated=True)

    async def generate_structured(self, request: ModelRequest) -> ModelResponse:
        with Timer() as t:
            text = await self._post(openai_style_messages(request))  # your transport here
        usage = TokenUsage(input_tokens=0, output_tokens=len(text) // 4, estimated=True)
        return build_response(
            provider=self.provider_id,
            model=self.model,
            finish=FinishReason.STOP,
            text=text,
            tool_call=None,
            usage=usage,
            latency_ms=t.elapsed_ms,
            want_structured=True,
        )

    async def generate(self, request: ModelRequest) -> ModelResponse:
        return await self.generate_structured(request)

    async def request_tool(self, request: ModelRequest) -> ModelResponse:
        raise CapabilityUnsupportedError("corp_gateway does not expose native tool calling")

    async def continue_after_tool(
        self, request: ModelRequest, tool_name: str, tool_result: str
    ) -> ModelResponse:
        return await self.generate_structured(request)

    def stream(self, request: ModelRequest) -> AsyncIterator[str]:
        raise CapabilityUnsupportedError("corp_gateway does not stream")
```

Rules:

- Raise `MalformedResponseError` when the vendor returns something that does not match the requested schema. Never guess.
- Raise `CapabilityUnsupportedError` for features you do not support. Never degrade silently.
- Set `estimated=True` on usage you computed yourself and leave `cost_is_estimated=True` unless the vendor reports cost.

## 2. Register it

Add a `ProviderEntry` to `soclab/providers/registry.py` with the environment variables it needs, its capabilities, an adapter version and the validation label `contract-tested against recorded fixtures` once step 3 exists.

## 3. Write the contract test

Record one real response for each of: structured output, tool proposal if supported, provider error, malformed output. Strip identifiers and any customer data. Save them under `tests/contract/providers/fixtures/` and add tests that build the adapter with a stub transport, following `test_provider_contract.py`.

## 4. Run a campaign

```bash
uv run soclab campaign --mode protected
```

The scoring report will label the provider by its validation level. Record the run in `docs/releases/` if you want to claim live validation.
