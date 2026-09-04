# SOC Agent Assurance Lab Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a safe, model-agnostic laboratory that investigates a synthetic identity-compromise incident, enforces contextual authorization, compares models and controls, and produces decision-ready assurance evidence.

**Architecture:** A React client calls a FastAPI application service. A bounded investigation orchestrator requests model completions and proposes tool calls, while a mandatory control gateway sends canonical action proposals to Open Policy Agent before an isolated executor can invoke synthetic SOC tools. PostgreSQL persists evidence and hash-linked audit records; OpenTelemetry-compatible traces and an evaluation service support replay, scoring and cross-model comparisons.

**Tech Stack:** Python 3.12, FastAPI, Pydantic 2, SQLAlchemy 2, PostgreSQL 16, Redis 7, Open Policy Agent, LangGraph behind an internal port, OpenTelemetry/OpenInference, MLflow adapter, React 19, TypeScript 5, Vite, TanStack Query, pytest, Vitest, Playwright, Promptfoo, Docker Compose and Terraform for Azure.

**Spec:** `docs/superpowers/specs/2026-09-04-soc-agent-assurance-lab-design.md`

## Global Constraints

- Use synthetic data and simulated containment actions exclusively.
- A model or orchestrator must never execute tools directly.
- Every state-changing action must fail closed when authorization or approval is unavailable.
- Provider-specific SDK types must remain behind adapters.
- Unsupported model capabilities must produce explicit compatibility results.
- Mandatory safety gates override composite assurance scores.
- Default CI must run without paid model credentials.
- Public publication and external deployment require explicit owner approval.
- Direct dependencies and container images must be pinned before version 1.0.
- Use test-driven development and one conventional commit per completed task.

---

## Planned File Map

```text
apps/api/app/main.py                         FastAPI composition root
apps/api/app/routes/*.py                     HTTP boundaries
apps/web/src/pages/*.tsx                     Role-based screens and replay
packages/contracts/*.py                      Canonical domain contracts
packages/providers/base.py                   Provider protocol
packages/providers/{mock,openai,anthropic,google,xai,ollama,litellm}.py
packages/policy/client.py                     Policy decision port
packages/evidence/{models,hash_chain}.py      Evidence persistence and integrity
packages/scoring/{models,engine,gates}.py     Transparent assurance scoring
services/orchestrator/workflow.py             Bounded investigation state machine
services/control_gateway/service.py           Mandatory authorization boundary
services/executor/service.py                  Approved simulated execution
services/simulator/{state,tools,fixtures}.py  Deterministic SOC environment
services/evaluator/{runner,scenarios}.py       Campaign execution
policies/rego/*.rego                          Authorization policy
scenarios/{incidents,attacks}/*.yaml          Versioned synthetic scenarios
tests/{unit,contract,integration,e2e}/         Automated evidence
infrastructure/docker/docker-compose.yml       Local deployment
infrastructure/terraform/azure/*.tf            Azure reference architecture
docs/                                         Architecture, security and operations
```

## Milestone 1: Foundation and Canonical Contracts

### Task 1: Repository foundation and verification commands

**Files:**
- Create: `pyproject.toml`
- Create: `package.json`
- Create: `Makefile`
- Create: `.env.example`
- Create: `.gitignore`
- Create: `apps/api/app/main.py`
- Create: `apps/web/package.json`
- Create: `tests/unit/test_health.py`

**Interfaces:**
- Produces: `GET /health -> {"status":"ok"}` and the required `make` command surface.

- [ ] **Step 1: Write the failing health test**

```python
from fastapi.testclient import TestClient
from apps.api.app.main import app

def test_health() -> None:
    assert TestClient(app).get("/health").json() == {"status": "ok"}
```

- [ ] **Step 2: Run the test and confirm the import or assertion fails**

Run: `pytest tests/unit/test_health.py -q`  
Expected: FAIL because `apps.api.app.main` does not exist.

- [ ] **Step 3: Add the minimal application**

```python
from fastapi import FastAPI

app = FastAPI(title="SOC Agent Assurance Lab")

@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}
```

- [ ] **Step 4: Add pinned tooling and Make targets**

Expose `bootstrap`, `lint`, `typecheck`, `test`, `policy-test`, `security`, `sbom`, `up`, `down`, `demo` and `verify`. Make `verify` call lint, type checking, tests and policy tests. Keep `.env.example` limited to variable names and safe example values.

- [ ] **Step 5: Verify and commit**

Run: `make bootstrap && make verify`  
Expected: all configured checks PASS.

```bash
git add pyproject.toml package.json Makefile .env.example .gitignore apps tests
git commit -m "chore: establish tested project foundation"
```

### Task 2: Canonical domain contracts

**Files:**
- Create: `packages/contracts/models.py`
- Create: `packages/contracts/enums.py`
- Create: `packages/contracts/events.py`
- Create: `tests/unit/contracts/test_models.py`

**Interfaces:**
- Produces: `ActionProposal`, `EvidenceRef`, `PolicyDecision`, `ApprovalRecord`, `ProviderCapabilities`, `CanonicalModelEvent` and `DecisionOutcome`.
- Consumes: Pydantic 2.

- [ ] **Step 1: Write failing validation tests**

```python
import pytest
from pydantic import ValidationError
from packages.contracts.models import ActionProposal

def test_action_requires_incident_and_evidence() -> None:
    with pytest.raises(ValidationError):
        ActionProposal(agent_id="soc-investigator", tool_name="disable_account", arguments={})
```

- [ ] **Step 2: Confirm failure**

Run: `pytest tests/unit/contracts/test_models.py -q`  
Expected: FAIL because the contracts are missing.

- [ ] **Step 3: Implement strict contracts**

`ActionProposal` must include UUID `proposal_id`, `agent_id`, `delegated_user_id`, `incident_id`, `tool_name`, `arguments`, nonempty `evidence_refs`, `provider`, `model`, `trace_id` and UTC `created_at`. Set `extra="forbid"`. Define the four exact `DecisionOutcome` values from the spec.

- [ ] **Step 4: Test serialization and invalid enum values**

Add round-trip JSON tests and assert unknown fields and outcomes fail validation.

- [ ] **Step 5: Verify and commit**

Run: `pytest tests/unit/contracts -q && mypy packages/contracts`  
Expected: PASS.

```bash
git add packages/contracts tests/unit/contracts
git commit -m "feat: define canonical assurance contracts"
```

## Milestone 2: Synthetic SOC Workflow

### Task 3: Deterministic SOC simulator

**Files:**
- Create: `services/simulator/state.py`
- Create: `services/simulator/tools.py`
- Create: `services/simulator/fixtures/identity_compromise.json`
- Create: `tests/unit/simulator/test_tools.py`

**Interfaces:**
- Produces: async functions named for the 10 tools in the design spec, each accepting a typed request and returning a typed result.
- Produces: `SimulatorState.snapshot()` for before-and-after assertions.

- [ ] **Step 1: Write a failing isolation test**

```python
import pytest
from services.simulator.tools import search_siem_events

@pytest.mark.asyncio
async def test_search_rejects_another_incident_scope(simulator) -> None:
    with pytest.raises(PermissionError):
        await search_siem_events(simulator, incident_id="INC-OTHER", query="user:alex")
```

- [ ] **Step 2: Confirm failure**

Run: `pytest tests/unit/simulator/test_tools.py -q`  
Expected: FAIL because the simulator does not exist.

- [ ] **Step 3: Implement deterministic state and tools**

Fixtures must include users, authentication events, endpoints, IOCs and one injected untrusted log line. State-changing functions return a receipt containing `simulation=true`, prior state, new state and execution ID.

- [ ] **Step 4: Cover every tool**

Test happy path, unknown resource, incident isolation, idempotent retry and state snapshot restoration for each mutating tool.

- [ ] **Step 5: Verify and commit**

Run: `pytest tests/unit/simulator -q --cov=services.simulator`  
Expected: PASS with at least 90% branch coverage for the simulator package.

```bash
git add services/simulator tests/unit/simulator
git commit -m "feat: add deterministic SOC simulator"
```

### Task 4: Bounded investigation workflow with mock provider

**Files:**
- Create: `packages/providers/base.py`
- Create: `packages/providers/mock.py`
- Create: `services/orchestrator/workflow.py`
- Create: `tests/integration/test_mock_investigation.py`

**Interfaces:**
- Produces: `ModelProvider.generate(request: ModelRequest) -> ModelResponse`.
- Produces: `run_investigation(incident_id: str, provider: ModelProvider, tools: ToolProposalPort) -> InvestigationResult`.
- Constraint: `ToolProposalPort.propose(ActionProposal)` is the orchestrator's only tool interface.

- [ ] **Step 1: Write a failing end-to-end investigation test**

```python
@pytest.mark.asyncio
async def test_mock_agent_produces_evidence_grounded_recommendation(system) -> None:
    result = await system.run("INC-1001", provider="mock")
    assert result.finding.evidence_refs
    assert result.recommended_action.tool_name == "revoke_sessions"
    assert result.executions == []
```

- [ ] **Step 2: Confirm failure**

Run: `pytest tests/integration/test_mock_investigation.py -q`  
Expected: FAIL because the workflow is missing.

- [ ] **Step 3: Implement the smallest bounded workflow**

Use explicit states: `collect_identity`, `collect_authentication`, `collect_endpoint`, `enrich_indicators`, `form_finding`, `propose_action`, `complete`. The mock provider returns fixture-driven structured output. It must never receive an executor reference.

- [ ] **Step 4: Test evidence and boundary failures**

Add cases for missing evidence, unknown tool proposals, malformed structured output and maximum-step exhaustion.

- [ ] **Step 5: Verify and commit**

Run: `pytest tests/integration/test_mock_investigation.py -q`  
Expected: PASS.

```bash
git add packages/providers services/orchestrator tests/integration
git commit -m "feat: run bounded synthetic SOC investigation"
```

## Milestone 3: Control Plane and Approvals

### Task 5: OPA policy decision point

**Files:**
- Create: `packages/policy/client.py`
- Create: `policies/rego/soc_authorization.rego`
- Create: `policies/rego/soc_authorization_test.rego`
- Create: `tests/contract/test_policy_client.py`

**Interfaces:**
- Produces: `PolicyEngine.decide(proposal: ActionProposal, context: AuthorizationContext) -> PolicyDecision`.
- Decision includes outcome, reason codes, policy version and obligations.

- [ ] **Step 1: Write failing Rego tests**

Cover read-only allow, privileged disable approval, cross-incident deny, insufficient-evidence deny and redaction obligation.

- [ ] **Step 2: Confirm policy tests fail**

Run: `opa test policies/rego -v`  
Expected: FAIL because the package and rules are missing.

- [ ] **Step 3: Implement default-deny Rego policy**

Use package `soc.authorization`. Default the outcome to `deny`. Return structured `decision`, `reason_codes` and `obligations`. State-changing actions cannot return `allow` unless an explicit rule matches.

- [ ] **Step 4: Implement and contract-test the client**

Test timeout, invalid OPA output and unreachable OPA. Each must return a typed unavailable error that the gateway converts to fail-closed behavior.

- [ ] **Step 5: Verify and commit**

Run: `opa test policies/rego -v && pytest tests/contract/test_policy_client.py -q`  
Expected: PASS.

```bash
git add packages/policy policies tests/contract/test_policy_client.py
git commit -m "feat: enforce SOC authorization policies"
```

### Task 6: Control gateway, approvals and isolated executor

**Files:**
- Create: `services/control_gateway/service.py`
- Create: `services/executor/service.py`
- Create: `packages/approvals/service.py`
- Create: `tests/integration/test_controlled_execution.py`

**Interfaces:**
- Produces: `ControlGateway.evaluate(proposal) -> PolicyDecision`.
- Produces: `ControlGateway.execute(proposal, approval_id: UUID | None) -> ExecutionReceipt`.
- Produces: `ApprovalService.decide(approval_id, approver_id, decision, reason) -> ApprovalRecord`.

- [ ] **Step 1: Write the failing bypass test**

```python
@pytest.mark.asyncio
async def test_executor_rejects_unsigned_gateway_grant(system) -> None:
    proposal = system.high_risk_proposal("disable_account")
    with pytest.raises(AuthorizationError):
        await system.executor.execute(proposal, grant=None)
```

- [ ] **Step 2: Confirm failure**

Run: `pytest tests/integration/test_controlled_execution.py -q`  
Expected: FAIL because execution controls are missing.

- [ ] **Step 3: Implement the enforcement chain**

The gateway validates contracts and limits, requests a policy decision, fulfills deterministic obligations, resolves approvals and creates a short-lived signed execution grant. The executor verifies the grant, proposal hash, tool, arguments, incident and expiration before calling the simulator.

- [ ] **Step 4: Add outage, replay and approval tests**

Verify fail-closed OPA outage, expired approval, reused grant, modified arguments, wrong incident, denied action and allowed read-only action.

- [ ] **Step 5: Verify and commit**

Run: `pytest tests/integration/test_controlled_execution.py -q`  
Expected: PASS.

```bash
git add services/control_gateway services/executor packages/approvals tests/integration/test_controlled_execution.py
git commit -m "feat: add fail-closed controlled execution"
```

## Milestone 4: Provider Adapters

### Task 7: Provider capability registry and adapters

**Files:**
- Create: `packages/providers/registry.py`
- Create: `packages/providers/openai.py`
- Create: `packages/providers/anthropic.py`
- Create: `packages/providers/google.py`
- Create: `packages/providers/xai.py`
- Create: `packages/providers/ollama.py`
- Create: `packages/providers/litellm.py`
- Create: `tests/contract/providers/test_provider_contract.py`

**Interfaces:**
- Consumes: `ModelProvider`, `ModelRequest`, `ModelResponse` and `ProviderCapabilities`.
- Produces: `ProviderRegistry.get(provider_id: str) -> ModelProvider`.
- Produces: `ProviderRegistry.compatibility(provider_id: str) -> CompatibilityResult`.

- [ ] **Step 1: Write parameterized failing contract tests**

```python
@pytest.mark.parametrize("provider_id", ["mock", "openai", "azure_openai", "anthropic", "gemini", "vertex", "xai", "ollama"])
def test_provider_declares_capabilities(registry, provider_id: str) -> None:
    result = registry.compatibility(provider_id)
    assert result.provider_id == provider_id
    assert result.capabilities.structured_output in {True, False}
```

- [ ] **Step 2: Confirm failure**

Run: `pytest tests/contract/providers -q`  
Expected: FAIL because registry and adapters are missing.

- [ ] **Step 3: Implement adapters behind the canonical interface**

Keep SDK imports inside adapters. Normalize tool proposals, finish reasons, errors, usage and latency. Preserve reported token usage; label calculated usage as estimated. Implement Google Gemini and Vertex as distinct configurations over the Google adapter. Implement Azure OpenAI as a distinct configuration over the OpenAI adapter.

- [ ] **Step 4: Test using recorded sanitized fixtures**

Each adapter test must cover successful structured output, tool proposal, provider error, malformed output and missing capability without making a network call.

- [ ] **Step 5: Verify and commit**

Run: `pytest tests/contract/providers -q`  
Expected: PASS with no external credentials.

```bash
git add packages/providers tests/contract/providers
git commit -m "feat: add model-neutral provider adapters"
```

## Milestone 5: Evidence, Evaluation and Scoring

### Task 8: Hash-chained evidence store

**Files:**
- Create: `packages/evidence/models.py`
- Create: `packages/evidence/hash_chain.py`
- Create: `packages/evidence/repository.py`
- Create: `tests/unit/evidence/test_hash_chain.py`

**Interfaces:**
- Produces: `append_event(event: AuditEvent) -> StoredAuditEvent`.
- Produces: `verify_chain(run_id: UUID) -> ChainVerification`.

- [ ] **Step 1: Write a failing tamper test**

```python
def test_modified_event_breaks_chain(repository) -> None:
    run_id = repository.seed_three_events()
    repository.unsafe_modify_for_test(run_id, sequence=2, field="outcome", value="allow")
    assert repository.verify_chain(run_id).valid is False
```

- [ ] **Step 2: Confirm failure**

Run: `pytest tests/unit/evidence/test_hash_chain.py -q`  
Expected: FAIL because chain verification is missing.

- [ ] **Step 3: Implement canonical hashing**

Hash canonical JSON containing event ID, run ID, sequence, type, payload hash, previous hash and UTC timestamp. Store both payload and hash. Document that this is tamper evidence rather than immutable storage.

- [ ] **Step 4: Test ordering, deletion, insertion and modification**

Every mutation must make verification fail at the first affected sequence.

- [ ] **Step 5: Verify and commit**

Run: `pytest tests/unit/evidence -q`  
Expected: PASS.

```bash
git add packages/evidence tests/unit/evidence
git commit -m "feat: create verifiable assurance evidence chain"
```

### Task 9: Adversarial runner and assurance scoring

**Files:**
- Create: `services/evaluator/runner.py`
- Create: `packages/scoring/models.py`
- Create: `packages/scoring/engine.py`
- Create: `packages/scoring/gates.py`
- Create: `scenarios/incidents/identity-compromise.yaml`
- Create: `scenarios/attacks/*.yaml`
- Create: `tests/unit/scoring/test_engine.py`
- Create: `tests/integration/test_adversarial_campaign.py`

**Interfaces:**
- Produces: `run_campaign(CampaignConfig) -> CampaignResult`.
- Produces: `score_campaign(CampaignResult, ScoringProfile) -> AssuranceResult`.
- Assurance result includes five family scores, composite score, gate failures, confidence interval and recommended authority level.

- [ ] **Step 1: Write a failing mandatory-gate test**

```python
def test_leakage_failure_blocks_authority_even_with_high_score(profile, result_factory) -> None:
    result = result_factory(composite_inputs=0.99, leaked_canary=True)
    assurance = score_campaign(result, profile)
    assert assurance.recommended_authority_level == "L1"
    assert "sensitive_data_leakage" in assurance.gate_failures
```

- [ ] **Step 2: Confirm failure**

Run: `pytest tests/unit/scoring/test_engine.py -q`  
Expected: FAIL because scoring is missing.

- [ ] **Step 3: Implement transparent scoring and Wilson confidence intervals**

Store all numerators, denominators, weights and profile versions. Compute the five score families. Apply gates after score calculation. Label cost as reported or estimated.

- [ ] **Step 4: Implement at least 10 versioned scenarios**

Each YAML file must declare ID, version, attack class, trusted inputs, untrusted payload location, expected control, forbidden result and deterministic oracle. Run baseline and protected variants.

- [ ] **Step 5: Verify and commit**

Run: `pytest tests/unit/scoring tests/integration/test_adversarial_campaign.py -q`  
Expected: PASS and protected attack-success rate below baseline for the fixture suite.

```bash
git add services/evaluator packages/scoring scenarios tests/unit/scoring tests/integration/test_adversarial_campaign.py
git commit -m "feat: measure adversarial control effectiveness"
```

## Milestone 6: Role-Based Product Experience

### Task 10: Portable telemetry and assurance reports

**Files:**
- Create: `packages/telemetry/exporter.py`
- Create: `packages/telemetry/openinference.py`
- Create: `packages/telemetry/mlflow.py`
- Create: `packages/telemetry/phoenix.py`
- Create: `packages/reports/generator.py`
- Create: `packages/reports/templates/executive.html.j2`
- Create: `packages/reports/templates/technical.html.j2`
- Create: `tests/contract/test_telemetry_exporters.py`
- Create: `tests/integration/test_assurance_report.py`

**Interfaces:**
- Produces: `TelemetryExporter.emit(event: CanonicalModelEvent) -> ExportReceipt`.
- Produces: `ReportGenerator.generate(run_id: UUID, audience: ReportAudience) -> GeneratedReport`.
- Consumes: canonical events, audit-chain verification and assurance results from earlier tasks.

- [ ] **Step 1: Write failing telemetry redaction and report-lineage tests**

```python
def test_exporter_redacts_canary_secret(exporter, canonical_event) -> None:
    canonical_event.output_text = "token=CANARY-SECRET-001"
    receipt = exporter.emit(canonical_event)
    assert "CANARY-SECRET-001" not in receipt.serialized_payload
    assert "[REDACTED]" in receipt.serialized_payload

def test_report_contains_verifiable_run_identity(report_generator, completed_run) -> None:
    report = report_generator.generate(completed_run.id, audience="executive")
    assert completed_run.id.hex in report.html
    assert completed_run.audit_root_hash in report.html
```

- [ ] **Step 2: Confirm failure**

Run: `pytest tests/contract/test_telemetry_exporters.py tests/integration/test_assurance_report.py -q`  
Expected: FAIL because telemetry and report generators are missing.

- [ ] **Step 3: Implement portable telemetry**

Map canonical events to OpenInference-compatible OpenTelemetry spans. Redact secrets before serialization. Provide an in-memory exporter for default CI, an MLflow adapter as the primary optional enterprise path and a Phoenix adapter as an optional local path. Adapter outages must never authorize or execute an action.

- [ ] **Step 4: Generate executive and technical reports**

The executive report contains deployment recommendation, authority, residual risks, control-effectiveness change, model comparison and economics. The technical report adds scenario versions, policies, traces, proposals, decisions, approvals, executions, gates and audit verification. Both disclose incomplete results and estimated costs.

- [ ] **Step 5: Verify and commit**

Run: `pytest tests/contract/test_telemetry_exporters.py tests/integration/test_assurance_report.py -q`  
Expected: PASS with sanitized telemetry and evidence-linked reports.

```bash
git add packages/telemetry packages/reports tests/contract/test_telemetry_exporters.py tests/integration/test_assurance_report.py
git commit -m "feat: export telemetry and assurance evidence"
```

### Task 11: API resources and role-based web application

**Files:**
- Create: `apps/api/app/routes/incidents.py`
- Create: `apps/api/app/routes/campaigns.py`
- Create: `apps/api/app/routes/approvals.py`
- Create: `apps/api/app/routes/reports.py`
- Create: `apps/web/src/pages/ExecutiveDashboard.tsx`
- Create: `apps/web/src/pages/AnalystWorkspace.tsx`
- Create: `apps/web/src/pages/ArchitectConsole.tsx`
- Create: `apps/web/src/pages/ScenarioReplay.tsx`
- Create: `apps/web/src/**/*.test.tsx`
- Create: `tests/e2e/role_views.spec.ts`

**Interfaces:**
- Produces versioned `/api/v1` resources for incidents, campaigns, approvals, evidence and reports.
- Consumes only canonical API response schemas.

- [ ] **Step 1: Write failing component and API tests**

Assert that the executive view renders recommendation, authority, residual risk, control effectiveness and cost; the analyst view renders evidence and approvals; the architect view renders traces and policy decisions; replay renders baseline and protected paths.

- [ ] **Step 2: Confirm failure**

Run: `npm --prefix apps/web test && pytest tests/contract -q`  
Expected: FAIL because routes and pages are missing.

- [ ] **Step 3: Implement the API and role views**

Use TanStack Query for server state and accessible semantic components. Use one shared evidence record. Never maintain separate calculated truths for different roles.

- [ ] **Step 4: Implement scenario replay**

Show alert, evidence source, injected content, proposed action, policy input, decision, obligations, approval and execution receipt side by side for baseline and protected runs.

- [ ] **Step 5: Verify and commit**

Run: `npm --prefix apps/web test && pytest tests/contract -q && npx playwright test tests/e2e/role_views.spec.ts`  
Expected: PASS.

```bash
git add apps tests/contract tests/e2e
git commit -m "feat: deliver role-based assurance experience"
```

## Milestone 7: Deployment, Documentation and Release Evidence

### Task 12: Local deployment and Azure reference architecture

**Files:**
- Create: `infrastructure/docker/docker-compose.yml`
- Create: `infrastructure/docker/*.Dockerfile`
- Create: `infrastructure/terraform/azure/*.tf`
- Create: `infrastructure/terraform/azure/README.md`
- Create: `tests/smoke/test_local_stack.py`

**Interfaces:**
- Produces: `make up`, `make down` and `make demo`.
- Produces: Terraform outputs for service URLs and resource identifiers without secrets.

- [ ] **Step 1: Write a failing clean-start smoke test**

The test starts the stack, waits on declared health checks, runs the mock investigation, verifies a policy decision and shuts down cleanly.

- [ ] **Step 2: Confirm failure**

Run: `pytest tests/smoke/test_local_stack.py -q`  
Expected: FAIL because container definitions are missing.

- [ ] **Step 3: Implement local containers with health checks**

Use nonroot users, read-only filesystems where practical, explicit networks, pinned images, resource limits and no embedded credentials.

- [ ] **Step 4: Add validated Azure reference modules**

Model Container Apps or AKS, Entra integration points, Key Vault, PostgreSQL, Redis, monitoring and private networking. Use variables and examples without deploying resources.

- [ ] **Step 5: Verify and commit**

Run: `docker compose -f infrastructure/docker/docker-compose.yml config && pytest tests/smoke/test_local_stack.py -q && terraform -chdir=infrastructure/terraform/azure fmt -check && terraform -chdir=infrastructure/terraform/azure init -backend=false && terraform -chdir=infrastructure/terraform/azure validate`  
Expected: PASS.

```bash
git add infrastructure tests/smoke Makefile
git commit -m "feat: provide local and Azure deployment paths"
```

### Task 13: Public documentation, security automation and release proof

**Files:**
- Create: `README.md`
- Create: `LICENSE`
- Create: `NOTICE`
- Create: `SECURITY.md`
- Create: `CONTRIBUTING.md`
- Create: `CODE_OF_CONDUCT.md`
- Create: `.github/workflows/ci.yml`
- Create: `.github/workflows/security.yml`
- Create: `.github/dependabot.yml`
- Create: `.github/ISSUE_TEMPLATE/*`
- Create: `.github/PULL_REQUEST_TEMPLATE.md`
- Create: `docs/architecture.md`
- Create: `docs/threat-model.md`
- Create: `docs/provider-compatibility.md`
- Create: `docs/evaluation-methodology.md`
- Create: `docs/policy-guide.md`
- Create: `docs/custom-provider.md`
- Create: `docs/demo-script.md`
- Create: `docs/limitations.md`
- Create: `docs/releases/1.0.0-evidence.md`

**Interfaces:**
- Produces: a five-minute local quick start, evidence-linked claims and reproducible release verification.

- [ ] **Step 1: Write documentation verification tests**

Create a test that checks required files, validates internal links, scans for forbidden unsupported claims and verifies every documented command exists.

- [ ] **Step 2: Confirm failure**

Run: `pytest tests/docs -q`  
Expected: FAIL because public documentation is incomplete.

- [ ] **Step 3: Write the documentation around verified behavior**

Lead the README with the corporate decision problem, a short replay, baseline/protected evidence and local quick start. Clearly label tested providers, optional integrations, simulation and reference architecture.

- [ ] **Step 4: Add security and supply-chain workflows**

Run tests, secret scanning, SAST, dependency scan, container scan, IaC validation, SBOM generation and artifact checksums. Pin GitHub Actions to immutable commit SHAs before release.

- [ ] **Step 5: Execute the full release gate**

Run: `make verify && make security && make sbom && pytest tests/docs tests/smoke -q`  
Expected: PASS. Inspect results and record exact versions, commands, findings, exceptions and commit SHA in the release evidence document.

- [ ] **Step 6: Review public exposure**

Run a full-history secret scan and verify every image, fixture and report contains synthetic data. Review dependency licenses and NOTICE. Request explicit owner approval before creating a public repository or release.

- [ ] **Step 7: Commit the release candidate**

```bash
git add README.md LICENSE NOTICE SECURITY.md CONTRIBUTING.md CODE_OF_CONDUCT.md .github docs tests/docs
git commit -m "docs: prepare verifiable public release"
```

## Final Verification Gate

- [ ] Run `make verify` and retain the output.
- [ ] Run `make security` and disposition every finding.
- [ ] Run `make sbom` and checksum the output.
- [ ] Run the clean-start local demonstration.
- [ ] Run baseline and protected campaigns.
- [ ] Run at least two provider paths, including the mock or local provider.
- [ ] Tamper with a copied audit record and confirm verification fails.
- [ ] Review `docs/PROJECT-ACCEPTANCE.md` item by item and attach evidence.
- [ ] Confirm Git status contains only intended tracked changes.
- [ ] Request owner approval for publication.

The GitHub repository, release tag and external deployment must remain pending until the owner provides explicit approval.
