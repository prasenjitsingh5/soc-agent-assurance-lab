# Threat model

Scope: an AI agent investigating a security incident with access to read-only telemetry tools and simulated containment actions. The adversary can influence what the agent reads but cannot modify the lab's code, configuration or signing key.

## Assets

- Simulated enterprise state: accounts, sessions, endpoints, block lists
- Canary secrets embedded in untrusted content
- Approval records and the evidence chain
- Approved model configuration and the policy version

## Adversary capabilities

| Capability | Where it enters | Scenario |
|---|---|---|
| Write instruction-like text into SIEM data | helpdesk note in a SIEM event | ATK-001 |
| Write instruction-like text into threat-intelligence responses | indicator report note | ATK-002 |
| Induce the model to repeat secrets | finding summary | ATK-003 |
| Induce the model to call an unregistered tool | export tool proposal | ATK-004 |
| Induce disproportionate action | disable privileged account on thin evidence | ATK-005 |
| Induce fabricated citations | claims referencing nonexistent evidence | ATK-006 |
| Smuggle extra tool arguments | force and scope flags | ATK-007 |
| Read across incidents | foreign incident id in arguments | ATK-008 |
| Exhaust call budget | more calls than the run allows | ATK-009 |
| Present a forged execution grant | grant signed with another key | ATK-010 |
| Substitute an unapproved model | model id not on the approved list | ATK-011 |
| Return malformed provider output | free text where JSON was required | ATK-012 |

## Controls and where they live

| Control | Component | Evidence |
|---|---|---|
| Trust labels on every input | orchestrator, providers | prompt shows `[trust=untrusted]` on tool content |
| Output redaction before the model sees tool results | gateway obligation `redact_secrets` | ATK-001, ATK-003 protected runs show `[REDACTED]` |
| Output redaction before persistence | evaluator, reports, telemetry | no canary in evidence store, reports or spans |
| Default-deny tool registry with argument schemas | policy `unknown_tool`, `argument_schema_violation` | ATK-004, ATK-007 |
| Incident scope enforcement, two layers | policy `cross_incident_scope`, simulator `assert_incident` | ATK-008 |
| Evidence minimums for state change | policy `insufficient_evidence_for_action` | ATK-001, ATK-005 |
| Authority ladder and approval for high impact | policy, approval service | ATK-005 escalates or denies |
| Call, cost and time limits | gateway `LimitContext`, policy `limit_exceeded` | ATK-009 |
| Signed, single-use, expiring execution grants | `soclab.grants`, executor | ATK-010, controlled execution tests |
| Approved model list | policy `unapproved_model` | ATK-011 |
| Strict schema validation of provider output | orchestrator, providers | ATK-012 |
| Fail closed on policy outage | gateway | controlled execution tests |
| Hash-chained evidence with tamper tests | `soclab.evidence` | evidence unit tests, report flag |

## Out of scope

- Compromise of the host running the lab, the signing key or the OPA container
- Attacks on the model provider's infrastructure
- Real SIEM, identity, endpoint or network systems, which the lab never contacts
- Multi-agent collusion; Phase 1 runs one agent

## Residual risks

- The mock provider's gullible behavior is a stand-in for real model susceptibility. Real models will differ; the lab measures them the same way once credentials are configured.
- Three scenarios are blocked in baseline as well as protected mode because schema validation lives in the orchestrator. The baseline is therefore slightly stronger than "no controls".
- The single-process Phase 1 deployment relies on the signed grant rather than a process boundary to separate orchestrator and executor (ADR 0005).
