# Provider compatibility

The lab does not promise identical capabilities across models. Each adapter declares what it supports and the registry reports what is missing. `soclab providers` prints the matrix from your environment.

## Validation levels

| Label | Meaning |
|---|---|
| deterministic | The mock provider. Runs in CI on every pull request. |
| contract-tested | The adapter is exercised against recorded, sanitized vendor responses with no network. Parsing, error mapping, usage and cost labeling are covered. |
| live-validated | A campaign has been run with real credentials and the result recorded in `docs/releases/`. No provider has this label yet. |

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
| ollama | native HTTP | model dependent | yes | yes | yes | contract-tested | `OLLAMA_BASE_URL` (default localhost) |
| openai_compatible | OpenAI-compatible adapter | yes | yes | yes | no, estimated | gateway path | `OPENAI_COMPATIBLE_BASE_URL` |

## Gateway path

Amazon Bedrock, Mistral, Cohere, Together, Groq, Fireworks, OpenRouter, vLLM and Hugging Face endpoints are reached through `openai_compatible` pointed at a LiteLLM proxy, a vLLM server or the vendor's OpenAI-compatible endpoint. Usage is estimated on this path unless the gateway forwards vendor usage fields.

## Cost labels

Every `ModelResponse` carries `cost_is_estimated`. Native adapters report vendor token counts and compute cost from a small list-price table that is itself labeled estimated. Ollama reports zero cost. The scoring engine and every report repeat the label.

## Adding a provider

See `docs/custom-provider.md`.
