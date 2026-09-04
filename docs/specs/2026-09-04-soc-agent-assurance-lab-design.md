# SOC Agent Assurance Lab

## Product and Technical Design Specification

**Status:** Approved design consolidated for review  
**Date:** September 4, 2026  
**Author:** Prasenjit Singh  
**Intended release:** Public GitHub reference implementation  

## 1. Executive Summary

The SOC Agent Assurance Lab is a model-agnostic reference implementation for measuring, controlling and documenting the behavior of AI agents used in security operations. It helps an organization answer three questions:

1. Which model and configuration can investigate a security incident most reliably?
2. Which controls must be enforced before the agent receives operational authority?
3. What evidence supports the resulting deployment decision?

The product includes a bounded AI SOC investigator, a deterministic security control plane, a synthetic enterprise-security environment, an adversarial test harness, cross-model comparisons and role-based dashboards. It runs locally without paid credentials and offers optional integrations for commercial models, enterprise identity, Azure deployment and observability platforms.

The reference agent is necessary to make the tests realistic. The distinguishing contribution is the assurance system around the agent: contextual authorization, authority levels, control-effectiveness measurement, evidence integrity and release recommendations.

### Product message

> Bring your model. Apply one security policy. Measure control effectiveness. Produce deployment evidence.

## 2. Market Position and Differentiation

Open-source AI SOC platforms already provide alert ingestion, IOC enrichment, MITRE ATT&CK mapping, investigation and playbook automation. Agent-security projects provide generic policy enforcement, tool authorization, approvals and audit trails. Red-team frameworks test prompt injection, leakage and jailbreaks. Observability platforms trace model and tool behavior.

The Lab combines these capabilities around a specific unresolved decision: whether a SOC agent has earned a defined level of operational authority.

### Deliberate boundaries

- It is not a replacement SIEM, SOAR or production SOC platform.
- It is not a general-purpose LLM vulnerability scanner.
- It is not a generic agent framework.
- It does not claim regulatory compliance or production readiness without evidence.
- It does not connect to real containment systems in the flagship release.

### Reference projects

- Agentic SOC Platform: https://github.com/FunnyWolf/agentic-soc-platform
- AI-SOC-Agent: https://github.com/M507/ai-soc-agent
- PouchNexus: https://github.com/NathanCavalcanti/pouchnexus
- Microsoft Agent Governance Toolkit: https://github.com/microsoft/agent-governance-toolkit
- Microsoft PyRIT: https://github.com/microsoft/PyRIT
- NVIDIA garak: https://github.com/NVIDIA/garak
- Promptfoo: https://github.com/promptfoo/promptfoo
- Open Policy Agent: https://github.com/open-policy-agent/opa
- LiteLLM: https://github.com/BerriAI/litellm
- Arize Phoenix: https://github.com/Arize-ai/phoenix
- OpenInference: https://github.com/Arize-ai/openinference

Dependencies will be used according to their licenses and documented interfaces. Their implementations will not be copied into the project.

## 3. Target Users

### Executive and risk leader

Needs a concise deployment recommendation, residual-risk view, authority level, model comparison and evidence package.

### SOC analyst

Needs an incident workspace showing evidence, findings, proposed actions, approvals and replayable decisions.

### Security or AI architect

Needs traces, tool calls, policy inputs, control decisions, test results, model metadata and integration details.

### AI engineer or evaluator

Needs provider adapters, repeatable scenarios, configurable scoring, CI execution and machine-readable results.

## 4. Flagship Use Case

The first complete workflow is identity-compromise investigation with governed containment.

### Synthetic alert

The scenario combines:

- impossible travel;
- repeated failed logins;
- a successful login from an unfamiliar location;
- access to a privileged resource; and
- suspicious endpoint activity.

### Agent responsibility

The agent may gather evidence, correlate activity, map relevant behavior to MITRE ATT&CK, assess confidence, draft findings and propose response actions. High-impact actions require approval. Low-risk, reversible simulated actions may qualify for bounded autonomy after the release meets defined assurance thresholds.

### Simulated tools

- `search_siem_events`
- `get_identity_profile`
- `get_authentication_history`
- `get_endpoint_status`
- `lookup_indicator`
- `create_incident`
- `revoke_sessions`
- `disable_account`
- `isolate_endpoint`
- `block_indicator`

Every tool uses synthetic, deterministic fixtures. State-changing tools modify simulated state only.

### Operating modes

1. **Baseline:** Weak controls expose agent vulnerabilities.
2. **Protected:** The same model and scenario run through the control plane.
3. **Comparison:** Multiple models run the same scenario and scoring profile.

## 5. Functional Requirements

### Investigation

- Accept a synthetic alert and create an investigation.
- Collect evidence through registered read-only tools.
- Preserve provenance for every evidence item.
- Create a finding whose claims link to evidence.
- Map relevant behavior to MITRE ATT&CK.
- Generate a structured response proposal.

### Authorization and execution

- Intercept every proposed tool action before execution.
- Validate agent identity, delegated user, incident scope, tool, arguments, evidence, destination, reversibility, rate and cost.
- Return `allow`, `allow_with_obligations`, `require_approval` or `deny`.
- Enforce obligations before execution.
- Require timely, attributable approval for high-impact actions.
- Execute approved calls through a separate executor.
- Default to fail-closed behavior for state-changing actions.

### Evaluation

- Run deterministic functional and adversarial scenarios.
- Repeat stochastic model runs to quantify variability.
- Compare baseline and protected configurations.
- Compare models using a common scenario, scoring profile and control configuration.
- Preserve raw results, normalized scores and calculation inputs.
- Detect regression after changes to models, prompts, tools, policies or code.

### Reporting

- Display executive, analyst and architect views over the same evidence.
- Replay the complete path from alert through action decision.
- Generate machine-readable JSON results.
- Generate an executive assurance report and technical evidence package.
- State limitations, unresolved risks and failed mandatory gates.

## 6. Adversarial Scenarios

The flagship release includes at least 10 tests across these attack classes:

1. Indirect prompt injection hidden in a SIEM event.
2. Malicious instructions returned by a threat-intelligence tool.
3. Canary-secret exfiltration attempt.
4. Sensitive incident-data transfer to an unapproved destination.
5. Unauthorized privileged-account disablement.
6. Unsupported conclusion or fabricated evidence.
7. Tool-argument manipulation.
8. Cross-incident data access.
9. Repeated calls creating a cost or execution loop.
10. Human-approval bypass.
11. Model substitution or downgrade to an unapproved model.
12. Malformed provider response intended to confuse validation.

The test suite is defensive, synthetic and intended for authorized evaluation.

## 7. Provider and Model Compatibility

### Compatibility promise

Any model can be connected through a native adapter, an OpenAI-compatible endpoint or the documented custom-provider interface.

The project does not promise identical capabilities across models. Each adapter reports supported features, and the runtime selects safe behavior based on those capabilities.

### Canonical model interface

Each provider adapter implements:

- `generate`
- `generate_structured`
- `request_tool`
- `continue_after_tool`
- `stream`
- `count_usage`
- `describe_capabilities`

### Initial provider tiers

**Tier 1, explicitly tested:**

- OpenAI
- Azure OpenAI
- Anthropic
- Google Gemini
- Google Vertex AI
- xAI Grok
- Ollama

**Tier 2, gateway supported:**

- Amazon Bedrock
- Mistral
- Cohere
- Together AI
- Groq
- Fireworks AI
- OpenRouter
- vLLM
- Hugging Face endpoints

**Tier 3, extensible:**

- proprietary corporate models;
- private fine-tuned models;
- sovereign-cloud endpoints;
- corporate AI gateways; and
- custom authentication and transport schemes.

### Capability registry

The registry records native tool calling, structured output, streaming, multimodal input, usage reporting, provider region, approved status and adapter version. Unsupported functionality results in an explicit compatibility result. Silent degradation is prohibited.

### Canonical event schema

Provider responses become a normalized internal event containing provider, model, agent, user delegation, incident, proposed tool, validated arguments, evidence references, risk tier, usage, estimated cost, policy result and trace identifiers.

Security controls operate on the canonical event rather than provider-specific payloads.

## 8. System Architecture

### Components

| Component | Responsibility | Proposed technology |
|---|---|---|
| Web application | Dashboards, investigation, approvals and comparison | React and TypeScript |
| Application API | Incidents, evidence, policies, tests and reports | Python FastAPI |
| Investigation orchestrator | Bounded SOC workflow | LangGraph behind an internal interface |
| Model gateway | Provider normalization and capability handling | Custom contract with optional LiteLLM adapter |
| Control gateway | Mandatory interception of action proposals | Python and strict schemas |
| Policy decision point | Deterministic authorization | Open Policy Agent |
| Tool executor | Approved simulated execution | Isolated Python service |
| SOC simulator | Synthetic SIEM, identity, endpoint and intelligence APIs | FastAPI and fixtures |
| Attack harness | Adversarial and regression campaigns | Promptfoo plus native pytest |
| Evidence store | Incidents, events, approvals and evaluations | PostgreSQL |
| Background execution | Campaign queue and transient state | Redis |
| Telemetry | Portable traces and metrics | OpenTelemetry and OpenInference |
| Evaluation adapter | Datasets, experiments and scoring | MLflow, with optional Phoenix adapter |

### Stable interfaces

- `ModelProvider`
- `PolicyEngine`
- `ToolAdapter`
- `TelemetryExporter`

Agent frameworks, policy engines, gateways and observability platforms remain replaceable behind these interfaces.

### Trust boundaries

- Alerts, logs, documents and tool output are untrusted data.
- Model output and action proposals are untrusted.
- The orchestrator has no direct access to SOC tools.
- Only the policy-controlled executor may alter simulated state.
- Secrets remain outside prompts and are resolved at controlled execution time.
- Incident context is isolated and scope checked.

## 9. Security Control Model

| Layer | Required controls |
|---|---|
| Identity | User, agent and service identities; delegation; session binding |
| Input | Trust labels, provenance, injection screening and content boundaries |
| Context | Incident isolation, classification and cross-case access prevention |
| Model | Provider registry, version pinning and downgrade detection |
| Tools | Default-deny registry, schema validation, risk tiers and constraints |
| Execution | Isolation, timeout, idempotency, rate limit and reversibility |
| Oversight | Risk-based approval, expiration, identity and reason capture |
| Output | Evidence grounding, unsupported-claim detection and redaction |
| Operations | Tracing, budgets, loop detection, kill switch and incident events |
| Governance | Policy versioning, ownership, testing and release evidence |

### Authority levels

| Level | Permitted authority |
|---|---|
| L1 Observe | Read synthetic telemetry |
| L2 Investigate | Correlate evidence and create findings |
| L3 Recommend | Propose containment actions |
| L4 Act with approval | Execute approved simulated actions |
| L5 Bounded autonomy | Execute narrowly defined, reversible simulated actions |

Promotion requires passing mandatory gates and meeting published thresholds. A critical regression can reduce authority automatically.

## 10. Assurance and Scoring

### Score families

1. **Security resilience:** attack resistance, leakage, privilege misuse and policy bypass.
2. **Investigation quality:** correct findings, grounding and ATT&CK mapping.
3. **Operational discipline:** tool choice, argument accuracy and completion.
4. **Governance readiness:** trace, approval and evidence completeness.
5. **Economic efficiency:** successful outcomes relative to cost, latency and control overhead.

Published default weights produce a composite score. Users may create versioned scoring profiles.

### Mandatory gates

The following conditions override the composite score:

- sensitive-data leakage;
- successful approval bypass;
- unauthorized state-changing action;
- missing audit evidence for a consequential decision;
- execution outside assigned incident scope; or
- use of an unapproved provider or model.

### Release recommendation inputs

- Composite score
- Mandatory-gate results
- Critical failures
- Confidence interval across repeated runs
- Change from approved baseline
- Residual risks
- Target authority level

## 11. Evidence Integrity

Each run records:

- scenario and dataset versions;
- provider and model identifiers;
- prompt, agent, tool and policy versions;
- agent and delegated-user identities;
- proposed and executed actions;
- evidence references and provenance;
- policy input, decision, obligations and explanation;
- approval identity, decision, reason and time;
- token usage, cost and latency;
- evaluation results; and
- a cryptographic link to the preceding audit event.

The MVP uses a hash-chained audit log. The production reference explains export to immutable enterprise storage. The hash chain provides tamper evidence and does not itself make the underlying database immutable.

## 12. User Experience

### Role-based home views

**Executive view:** Deployment recommendation, authority level, residual risk, control effectiveness, model comparison, economics and open decisions.

**Analyst view:** Incident timeline, evidence, findings, proposed actions, approval queue and investigation state.

**Architect view:** Provider configuration, canonical events, traces, policy evaluation, tool calls, attack results and regression details.

### Signature scenario replay

A replay page presents baseline and protected executions side by side. It shows where malicious content entered, what action the agent proposed, which policy evaluated it, why the request was allowed or blocked and how that result affected the assurance recommendation.

## 13. Error Handling and Degraded Operation

- State-changing actions fail closed when any authorization dependency is unavailable.
- Read-only operation may continue only under an explicit degraded-mode policy.
- Partial results carry an incomplete status and cannot support promotion.
- Provider retries are bounded and use idempotency controls where applicable.
- Malformed provider responses fail schema validation.
- Approval requests expire and cannot be replayed.
- Cost, call-count and elapsed-time limits stop runaway execution.
- Every degradation creates an operational-security event.

## 14. Deployment Profiles

### Local

- Docker Compose
- Ollama or deterministic mock provider
- PostgreSQL, Redis and OPA
- No paid credentials required

### Bring your own model

- Provider selected by configuration
- Secrets loaded through excluded local configuration or a secret manager
- Identical scenarios, controls and scoring across providers

### Azure reference

- Azure Container Apps or Kubernetes
- Azure OpenAI
- Microsoft Entra ID
- Azure Key Vault
- Azure Database for PostgreSQL
- Managed Redis
- Private connectivity
- Azure Monitor
- Optional MLflow deployment
- Terraform reference modules

The Azure profile is a reference architecture. The canonical interfaces preserve deployment portability.

## 15. Test Strategy

| Test type | Coverage |
|---|---|
| Unit | Schemas, scores, risk classification, evidence hashes and cost |
| Contract | Provider, policy, tool and telemetry adapters |
| Policy | Allow, obligation, approval and denial paths |
| Integration | End-to-end service interactions |
| Adversarial | Injection, leakage, excessive agency and bypass attempts |
| Cross-model | Common scenarios and normalized measurements |
| Regression | Model, prompt, policy, tool and application changes |
| Failure | Timeout, outage, malformed response and fail-closed behavior |
| UI | Executive, analyst, architect and approval flows |
| Supply chain | Code, secret, dependency, container and IaC scanning |

Live provider tests are optional and require configured credentials. Default continuous integration uses deterministic fixtures and mocked provider responses.

## 16. GitHub Quality and Documentation

### Pull-request checks

- Python and TypeScript linting
- Unit and integration tests
- OPA policy tests
- Deterministic adversarial tests
- Secret scanning
- Static application-security analysis
- Dependency and container scanning
- Software bill of materials
- Infrastructure validation
- License checks
- Coverage reporting

### Documentation set

- Executive overview
- Five-minute quick start
- Architecture decision records
- Threat model and trust boundaries
- Provider compatibility matrix
- Authority and policy guides
- Evaluation and scoring methodology
- Attack-to-control matrix
- Azure reference architecture
- Security and responsible-disclosure policy
- Contribution guide
- Demonstration script
- Limitations and known risks
- Roadmap

## 17. Repository Structure

```text
soc-agent-assurance/
├── apps/
│   ├── web/
│   └── api/
├── services/
│   ├── orchestrator/
│   ├── model-gateway/
│   ├── control-gateway/
│   ├── executor/
│   └── soc-simulator/
├── packages/
│   ├── contracts/
│   ├── provider-adapters/
│   ├── tool-adapters/
│   ├── scoring/
│   └── evidence/
├── policies/
│   ├── rego/
│   └── tests/
├── scenarios/
│   ├── incidents/
│   └── attacks/
├── evaluations/
├── infrastructure/
│   ├── docker/
│   └── terraform/azure/
├── docs/
└── tests/
```

## 18. Version 1.0 Acceptance Criteria

- Starts locally through Docker from documented prerequisites.
- Runs without paid credentials using the mock provider or Ollama.
- Implements one complete identity-compromise workflow.
- Provides at least five working provider paths, including the local path.
- Includes at least 10 deterministic adversarial scenarios.
- Routes every state-changing call through policy enforcement.
- Requires human approval for high-impact actions.
- Reproduces baseline and protected comparisons.
- Compares models across quality, security, latency and cost.
- Produces a verifiable hash-chained evidence record.
- Provides executive, analyst and architect views.
- Includes the scenario-replay experience.
- Keeps all containment integrations simulated.
- Passes automated security and quality checks.
- Documents architecture, threats, controls, tests, limitations and deployment.

## 19. Out of Scope for Version 1.0

- Direct integration with production SIEM, SOAR, identity or endpoint systems
- Real account disablement, endpoint isolation or network blocking
- Offensive exploitation or malware execution
- Multi-agent orchestration
- Additional incident families such as ransomware and insider threat
- Formal certification or compliance attestation
- Hosted multi-tenant SaaS
- Automated authority beyond reversible simulated actions

## 20. Implementation Principles

- Deterministic enforcement surrounds probabilistic reasoning.
- The model proposes; the control plane authorizes; the executor acts.
- Every consequential claim and action links to evidence.
- Provider differences remain explicit.
- Security tests are repeatable and versioned.
- Scores support decisions and never override mandatory safety gates.
- Local execution remains accessible to reviewers.
- Documentation distinguishes implemented, simulated, optional and planned capabilities.
- Scope favors one complete, polished workflow over broad shallow coverage.

## 21. Success Definition

The project succeeds when an executive can understand the deployment recommendation within two minutes, a security architect can trace that recommendation to enforceable controls and evidence, and an engineer can reproduce the result locally against more than one model provider.

