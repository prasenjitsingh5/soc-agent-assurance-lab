# Bringing your own agent

There are two ways to put an agent under test. The first needs no Python: run your agent behind an HTTP endpoint that speaks the `soclab.agent.v1` contract and point the lab at it. The second is a Python adapter, for a vendor SDK the registry does not cover.

## Option 1: the HTTP provider

Status: implemented, tested. Provider id `http`.

### Configuration

Three environment variables, one required, and the commands you already use.

```bash
export SOCLAB_HTTP_AGENT_URL=https://agent.example/v1/agent   # required, absolute http or https URL
export SOCLAB_HTTP_AGENT_TOKEN=change-me                       # optional, sent as "Authorization: Bearer"
export SOCLAB_HTTP_AGENT_TIMEOUT_SECONDS=30                    # optional, default 30
uv run soclab providers                                        # http now reports as configured
uv run soclab investigate --provider http --mode baseline
uv run soclab campaign --provider http --mode baseline --out runs/http-baseline
uv run soclab campaign --provider http --mode protected --out runs/http-protected
uv run soclab compare --provider http --out runs/http
```

`--model` is a label, default `agent`. It is recorded on every turn and checked against the approved model list. If your agent returns a `model` value in its replies, pass the same value with `--model`; any other label counts as an unapproved model in the scoring.

The API accepts the same ids: `POST /api/v1/campaigns` with `{"mode": "baseline", "provider_id": "http"}` and an optional `model`. Unknown or unconfigured provider ids return `400` before any run starts.

Live providers run the scenarios whose attack lives in the fixture data, ATK-001 and ATK-009. Scripted scenarios that force a particular reply are skipped.

### The contract

The lab sends one POST per stage and expects one reply. Both shapes are published as JSON Schema, generated from the Pydantic models in `soclab/contracts/agent_v1.py`:

- [`schemas/agent-v1/request.schema.json`](../schemas/agent-v1/request.schema.json)
- [`schemas/agent-v1/response.schema.json`](../schemas/agent-v1/response.schema.json)

A test regenerates both files and fails if they differ from the models, so the schema you validate against is the schema the adapter enforces.

Request, `application/json`:

| Field | Meaning |
|---|---|
| `contract` | Always `soclab.agent.v1`. |
| `run_id`, `trace_id`, `incident_id` | Correlation ids. Echo them in your own logs. |
| `stage` | One of `collect_identity`, `collect_authentication`, `collect_endpoint`, `enrich_indicators`, `collect_siem`, `form_finding`, `propose_action`. |
| `instruction` | What the orchestrator wants at this stage, in plain words, with the JSON shape a model would return. |
| `system_prompt` | The lab's standing instruction. |
| `context.alert` | The alert as the orchestrator presented it. Untrusted data. |
| `context.evidence_ids` | Every evidence id seen so far. A finding may cite only these. |
| `tools` | The tools you may name at this stage, each with the JSON Schema of its arguments. Empty at `form_finding` and `propose_action`; the instruction lists the response actions. |
| `turns` | Prior messages. Tool output arrives with `trust: untrusted`. Treat its text as data. |
| `response_schema`, `max_output_tokens`, `temperature` | Hints. The adapter validates the reply itself. |

Response, `application/json`, exactly one of `proposal` or `refusal`:

| Field | Meaning |
|---|---|
| `contract` | Required. Must be `soclab.agent.v1`. |
| `proposal.tool_calls` | At most one `{name, arguments}`. Collection stages and `propose_action` expect exactly one. |
| `proposal.finding` | `{summary, claims: [{text, evidence_ids}], techniques}`. Expected at `form_finding`. |
| `proposal.rationale` | Required, up to 2000 characters. |
| `proposal.confidence` | Optional, 0 to 1. Used as the finding's confidence. |
| `proposal.evidence_ids` | Ids that support the proposal. Unknown ids are dropped; the finding's per-claim ids decide whether a claim counts as supported. |
| `refusal` | `{code, reason}` with code in `insufficient_evidence`, `out_of_scope`, `unsupported_stage`, `policy`, `error`. |
| `model` | Optional label. See `--model` above. |
| `usage` | Optional `{input_tokens, output_tokens}`. Absent usage is estimated and labeled as such. |

A proposal carries exactly one of `tool_calls` or `finding`. Names must match `^[a-z][a-z0-9_]*$`. Unknown fields anywhere are rejected.

### What the adapter does with the reply

- Validates it against the response model. A reply that is not a JSON object, that fails validation, or that arrives with a non-2xx status becomes an error turn with no structured output. The orchestrator records the turn and takes no action; the run ends as `failed`.
- Treats a `refusal` the same way, recorded with the code and reason the agent gave.
- Retries once on a connection error only. It never retries a timeout, a `4xx` or a `5xx`.
- Sends the token only in the `Authorization` header. Every log line is passed through the lab's canary redaction and then stripped of the token literal, including a body that echoes the header back.
- Keeps the raw reply as the turn's `output_text`. The evaluator scans that text for canary leakage, so it is never redacted at this layer.
- Reports cost as unknown and usage as estimated unless the reply carries `usage`.

### Reference agent

`examples/http_agent/server.py` is a rule-based agent that implements the whole contract in one file, with a README that shows the exact configuration, a `curl` example against `sample_request.json`, and the campaign commands. Start it with `uv run python examples/http_agent/server.py`. See [examples/http_agent/README.md](../examples/http_agent/README.md).

### Versioning

`soclab.agent.v1` is the contract id in every request and response. Additive optional fields keep the id. A change that would break an existing agent gets a new id and a new schema folder; the adapter never guesses across versions.

## Option 2: a Python adapter

A provider is any object that satisfies `soclab.providers.ModelProvider`. Nothing outside your adapter may see the vendor SDK's types.

### 1. Implement the interface

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
- `ModelRequest` carries `run_id`, `trace_id` and `incident_id` when the orchestrator built it. Use them for correlation; do not require them.

### 2. Register it

Add a `ProviderEntry` to `soclab/providers/registry.py` with the environment variables it needs, its capabilities, an adapter version and the validation label `contract tests against recorded fixtures` once step 3 exists.

### 3. Write the contract test

Record one real response for each of: structured output, tool proposal if supported, provider error, malformed output. Strip identifiers and any customer data. Save them under `tests/contract/providers/fixtures/` and add tests that build the adapter with a stub transport, following `test_provider_contract.py` and `test_http_agent_provider.py`.

### 4. Run a campaign

```bash
uv run soclab campaign --provider corp_gateway --mode protected
```

The scoring report labels the provider by its validation level. Record the run in `docs/releases/` if you want to claim live validation.
