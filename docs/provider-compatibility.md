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

## Running a live provider

```bash
uv run soclab compare --provider ollama --model llama3.2:3b --out runs/ollama
uv run soclab campaign --provider openai --mode protected
```

Live providers run only the scenarios whose attack lives in the fixture data (ATK-001 injected SIEM note, ATK-009 call budget). Scenarios that script the mock's replies are skipped, because a real model cannot be forced to answer a particular way. Every stage sends the model an explicit instruction naming the JSON shape it must return, and native tool calls are accepted as equivalent to that JSON.

## Gateway path

Amazon Bedrock, Mistral, Cohere, Together, Groq, Fireworks, OpenRouter, vLLM and Hugging Face endpoints are reached through `openai_compatible` pointed at a LiteLLM proxy, a vLLM server or the vendor's OpenAI-compatible endpoint. Usage is estimated on this path unless the gateway forwards vendor usage fields.

## Cost labels

Every `ModelResponse` carries `cost_is_estimated`. Native adapters report vendor token counts and compute cost from a small list-price table that is itself labeled estimated. Ollama reports zero cost. The scoring engine and every report repeat the label.

## Adding a provider

See `docs/custom-provider.md`.
