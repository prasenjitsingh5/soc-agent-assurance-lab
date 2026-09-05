# Provider compatibility

The lab does not promise identical capabilities across models. Each adapter declares what it supports and the registry reports what is missing. `soclab providers` prints the matrix from your environment.

## Validation levels

| Label | Meaning |
|---|---|
| deterministic | The mock provider. Runs in CI on every pull request. |
| contract-tested | The adapter is exercised against recorded, sanitized vendor responses with no network. Parsing, error mapping, usage and cost labeling are covered. |
| live-validated | A campaign has been run against a real model and the result recorded in `docs/releases/`. Ollama with llama3.2:3b holds this label as of 2026-09-04. |

## Matrix

| Provider id | Path | Tool calling | Structured output | Streaming | Usage reporting | Validation | Required configuration |
|---|---|---|---|---|---|---|---|
| mock | built in | yes | yes | no | yes | deterministic | none |
| openai | native SDK | yes | yes | yes | yes | contract-tested | `OPENAI_API_KEY` |
| azure_openai | native SDK, Azure configuration | yes | yes | yes | yes | contract-tested | `AZURE_OPENAI_API_KEY`, `AZURE_OPENAI_ENDPOINT` |
| anthropic | native SDK | yes | yes | yes | yes | contract-tested | `ANTHROPIC_API_KEY` |
| gemini | google-genai | yes | yes | yes | yes | contract-tested | `GOOGLE_API_KEY` |
| vertex | google-genai, Vertex configuration | yes | yes | yes | yes | contract-tested | `GOOGLE_CLOUD_PROJECT`, `GOOGLE_CLOUD_LOCATION` |
| xai | OpenAI-compatible adapter | yes | yes | yes | yes | contract-tested via OpenAI adapter | `XAI_API_KEY` |
| ollama | native HTTP | model dependent | yes | yes | yes | live-validated (llama3.2:3b, 2026-09-04) | `OLLAMA_BASE_URL` (default localhost) |
| openai_compatible | OpenAI-compatible adapter | yes | yes | yes | no, estimated | gateway path | `OPENAI_COMPATIBLE_BASE_URL` |
| http | your own agent over HTTP, `soclab.agent.v1` contract | yes | yes | no | optional, estimated when absent | contract-tested, end-to-end tested against the reference agent | `SOCLAB_HTTP_AGENT_URL`; optional `SOCLAB_HTTP_AGENT_TOKEN`, `SOCLAB_HTTP_AGENT_TIMEOUT_SECONDS` |

## Running a live provider

```bash
uv run soclab compare --provider ollama --model llama3.2:3b --out runs/ollama
uv run soclab campaign --provider openai --mode protected
uv run soclab campaign --provider http --mode protected
```

Live providers run only the scenarios whose attack lives in the fixture data or is performed by the harness: the seven injection channels (ATK-001, ATK-013 to ATK-019), the call budget (ATK-009), the authority-claim note (ATK-028) and the replay, swap and tampering attacks (ATK-023, ATK-024, ATK-026), thirteen in all. The forged-grant scenario (ATK-010) scripts the proposal and stays with the mock. Scenarios that script the mock's replies are skipped, because a real model cannot be forced to answer a particular way. Every stage sends the model an explicit instruction naming the JSON shape it must return, and native tool calls are accepted as equivalent to that JSON.

## Gateway path

Amazon Bedrock, Mistral, Cohere, Together, Groq, Fireworks, OpenRouter, vLLM and Hugging Face endpoints are reached through `openai_compatible` pointed at a LiteLLM proxy, a vLLM server or the vendor's OpenAI-compatible endpoint. Usage is estimated on this path unless the gateway forwards vendor usage fields.

## Bring your own agent

An agent that is not a bare model, or a model behind a framework the registry does not know, runs through `http`. The lab POSTs one `soclab.agent.v1` request per stage to `SOCLAB_HTTP_AGENT_URL` and validates the reply against a published JSON Schema. Invalid replies, timeouts and error statuses fail closed as turns with no action. A rule-based reference agent ships in `examples/http_agent/`. Configuration and the contract are in `docs/custom-provider.md`.

## Cost labels

Every `ModelResponse` carries `cost_is_estimated`. Native adapters report vendor token counts and compute cost from a small list-price table that is itself labeled estimated. Ollama reports zero cost. The scoring engine and every report repeat the label.

## Adding a provider

See `docs/custom-provider.md`.
