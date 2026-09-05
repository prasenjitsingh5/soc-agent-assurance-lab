# Architecture

The lab answers one decision: has an AI SOC agent, with a given model and a given set of controls, earned a defined level of operational authority? Everything in the repository exists to produce evidence for that decision.

## The invariant

```
model proposes  ->  control gateway normalizes  ->  policy decides  ->  executor acts
```

- **Model output is untrusted.** Every tool call the model wants becomes an `ActionProposal`, a strict contract with evidence references, identities and a trace id.
- **The orchestrator holds no executor.** Its only tool interface is `ToolProposalPort.propose`. A test asserts that every proposal crosses that port.
- **The gateway builds the authorization context.** Authority level, approved models, tool registry, limits and approval state come from configuration and the approval service, never from the model.
- **Open Policy Agent decides.** A default-deny Rego package returns `allow`, `allow_with_obligations`, `require_approval` or `deny` with reason codes. Any outage fails closed for state-changing tools.
- **A signed grant authorizes execution.** The gateway issues an HMAC grant bound to the proposal hash; the executor verifies it, refuses reuse, and only then touches the simulator (ADR 0003).
- **Everything is hash-chained.** Model turns, tool outputs, findings, gateway events and receipts are appended to a per-run chain. Verification reports the first sequence that diverges.

## Components

| Package | Responsibility | Status |
|---|---|---|
| `soclab.contracts` | Canonical Pydantic contracts shared by every component | implemented |
| `soclab.simulator` | Ten synthetic SOC tools over fixture state with scope isolation and receipts | simulated |
| `soclab.orchestrator` | Seven-stage bounded investigation, evidence registry, unsupported-claim detection | implemented |
| `soclab.providers` | Canonical model interface, mock provider, adapters for OpenAI, Azure OpenAI, xAI, OpenAI-compatible, Anthropic, Gemini, Vertex, Ollama, HTTP bring-your-own-agent, registry | implemented, fixture tested |
| `soclab.contracts.agent_v1`, `schemas/agent-v1`, `examples/http_agent` | Versioned `soclab.agent.v1` request and response contract for external agents, published JSON Schema generated from the models, rule-based reference agent | implemented, tested |
| `soclab.policy` | Rego package, HTTP and subprocess engines, managed OPA server | implemented |
| `soclab.gateway`, `soclab.grants`, `soclab.executor`, `soclab.approvals` | Control plane, signed grants, isolated execution, human approvals | implemented |
| `soclab.evidence` | Hash-chained audit store on SQLAlchemy | implemented |
| `soclab.evaluator`, `scenarios/` | Twelve versioned attack scenarios, baseline and protected campaigns | implemented |
| `soclab.scoring` | Five score families, mandatory gates, Wilson intervals, authority recommendation | implemented |
| `soclab.telemetry` | OpenInference-style spans, redaction, in-memory, JSONL, optional MLflow and Phoenix | implemented, optional integration |
| `soclab.reports` | Executive and technical HTML and JSON from one evidence record | implemented |
| `soclab.cli`, `soclab.api` | Command line and versioned HTTP API | implemented |
| `infrastructure/docker` | Local profile: API, OPA, PostgreSQL, Redis | implemented |
| Web application | Role-based views and scenario replay | planned, Phase 2 |
| Azure reference | Terraform for Container Apps, Entra, Key Vault, PostgreSQL, Monitor | planned, Phase 3 |

## Trust boundaries

```
+---------------------------------------------------------------------+
|  untrusted: alert, SIEM events, identity, endpoint and TI tool output |
+---------------------------------------------------------------------+
            |  labeled untrusted, redacted before the model sees it
            v
+------------------------+        ActionProposal        +---------------------+
|  model provider (any)  | ---------------------------> |  control gateway    |
|  proposals only        | <--------------------------- |  context, policy,   |
+------------------------+        ProposalResult        |  obligations, grant |
                                                        +----------+----------+
                                                                   | signed grant
                                                                   v
                                 +----------------+       +-------------------+
                                 |  OPA (Rego)    | <---- |  executor         |
                                 |  default deny  |       |  verifies, runs   |
                                 +----------------+       +---------+---------+
                                                                    |
                                                                    v
                                                        +-----------------------+
                                                        |  simulator (synthetic) |
                                                        +-----------------------+
            every step  ----------------------------->  hash-chained evidence store
```

## Authority levels

| Level | Permits | Policy behavior |
|---|---|---|
| L1 Observe | read-only tools | allow with redaction |
| L2 Investigate | same, plus findings | state changes denied |
| L3 Recommend | propose actions | state changes denied, proposal recorded |
| L4 Act with approval | execute after a human approves | low and high risk both require approval |
| L5 Bounded autonomy | execute reversible low-risk actions unattended | high risk still requires approval |

The scoring engine recommends a level from the composite score and thresholds, then caps it at L1 when any mandatory gate fails or any attack succeeds in protected mode.

## Decisions

See `docs/adr/` for the recorded deviations from the original plan: single package layout, phased delivery without LangGraph, signed grants, named oracle predicates, and Docker profile boundaries.
