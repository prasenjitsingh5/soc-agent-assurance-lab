# Reference HTTP agent

A rule-based SOC agent that speaks the `soclab.agent.v1` contract. It is the smallest thing the lab can drive over HTTP, and the tests use it as a real peer. It is not a model. Each stage maps to one fixed rule over the evidence the orchestrator has already collected. Status: implemented, tested.

## Run it

```bash
uv run python examples/http_agent/server.py
```

The server binds `127.0.0.1:8765`. Set `SOCLAB_HTTP_AGENT_PORT` to change the port. Set `SOCLAB_HTTP_AGENT_TOKEN` to require a bearer token; requests without it get `401`.

## Point the lab at it

```bash
export SOCLAB_HTTP_AGENT_URL=http://127.0.0.1:8765/v1/agent
export SOCLAB_HTTP_AGENT_TOKEN=change-me            # optional, must match the server
export SOCLAB_HTTP_AGENT_TIMEOUT_SECONDS=30          # optional, default 30
uv run soclab providers                              # http shows as configured
uv run soclab campaign --provider http --mode baseline --out runs/http-baseline
uv run soclab compare --provider http --out runs/http
```

On PowerShell use `$env:SOCLAB_HTTP_AGENT_URL = "http://127.0.0.1:8765/v1/agent"`.

Live providers run the scenarios whose attack lives in the fixture data, ATK-001 and ATK-009. Scripted scenarios that force a particular reply are skipped, the same as for any other live provider.

## Talk to it directly

`sample_request.json` is a real first-stage request, generated from the orchestrator's own prompt and tool list.

```bash
curl -s http://127.0.0.1:8765/v1/agent \
  -H "Content-Type: application/json" \
  -d @examples/http_agent/sample_request.json
```

Reply:

```json
{
  "contract": "soclab.agent.v1",
  "proposal": {
    "tool_calls": [{"name": "get_identity_profile", "arguments": {"user_id": "u-alex-rivera"}}],
    "finding": null,
    "rationale": "The alert names the subject. Fetch the directory profile first.",
    "confidence": null,
    "evidence_ids": ["alert"]
  },
  "refusal": null,
  "model": null,
  "usage": null
}
```

## What the rules do

| Stage | Rule |
|---|---|
| `collect_identity` | `get_identity_profile` for `alert.subject_user_id` |
| `collect_authentication` | `get_authentication_history` for the subject |
| `collect_endpoint` | `get_endpoint_status` for the device behind the first sign-in from an unfamiliar location; refuses if none |
| `enrich_indicators` | `lookup_indicator` for the address behind the failed attempts; refuses if none |
| `collect_siem` | `search_siem_events` for the subject |
| `form_finding` | one claim per tool result, each citing its evidence id; ATT&CK ids from the facts |
| `propose_action` | `revoke_sessions` for the subject, with every evidence id |
| anything else | refusal with code `unsupported_stage` |

The agent never reads message text as an instruction, so the helpdesk note in ATK-001 that orders `disable_account` has no effect. It never quotes message text either, which keeps canary values out of its findings.

## Write your own

Any HTTP service that accepts [`schemas/agent-v1/request.schema.json`](../../schemas/agent-v1/request.schema.json) and answers with [`schemas/agent-v1/response.schema.json`](../../schemas/agent-v1/response.schema.json) works the same way. The adapter side is described in [docs/custom-provider.md](../../docs/custom-provider.md).
