# Project Acceptance and Release Checklist

## Product

- [ ] A clean clone starts through the documented local Docker workflow.
- [ ] The mock-provider path requires no paid credentials.
- [ ] Ollama is supported as an optional local-model path.
- [ ] One identity-compromise investigation runs from alert through evidence and recommendation.
- [ ] Baseline and protected modes use the same scenario and comparable configuration.
- [ ] Comparison mode runs the same scenario against at least two provider paths.
- [ ] Executive, analyst and architect views use the same underlying evidence.
- [ ] Scenario replay shows the alert, untrusted content, proposed action, policy decision and outcome.

## Model compatibility

- [ ] Canonical provider contracts are independent of provider SDK types.
- [ ] Capability discovery reports tool calling, structured output, streaming and usage reporting.
- [ ] Unsupported capabilities produce explicit compatibility results.
- [ ] OpenAI adapter contract tests pass.
- [ ] Azure OpenAI adapter contract tests pass.
- [ ] Anthropic adapter contract tests pass.
- [ ] Gemini adapter contract tests pass.
- [ ] Vertex AI adapter contract tests pass.
- [ ] xAI Grok adapter contract tests pass.
- [ ] Ollama adapter contract tests pass.
- [ ] LiteLLM or OpenAI-compatible extension path is documented and tested with a fixture.
- [ ] Custom-provider tutorial includes a complete example and contract test.

## Security control plane

- [ ] Every tool request crosses the control gateway.
- [ ] The orchestrator has no direct executor or simulator credentials.
- [ ] Default-deny tool policy is verified.
- [ ] Tool arguments are schema validated.
- [ ] Incident scope is enforced.
- [ ] Cross-incident access is denied and tested.
- [ ] High-impact actions require unexpired human approval.
- [ ] Approval identity, decision, reason and time are recorded.
- [ ] Obligations execute before the underlying tool.
- [ ] State-changing actions fail closed during policy or approval outages.
- [ ] Rate, call-count, elapsed-time and cost limits are enforced.
- [ ] Unapproved provider or model substitution is blocked.
- [ ] Canary secrets are redacted from outputs and telemetry.

## Evaluation

- [ ] At least 10 deterministic adversarial scenarios run in CI.
- [ ] Baseline and protected attack-success rates are calculated reproducibly.
- [ ] False blocks are measured.
- [ ] Unsupported claims are scored against evidence references.
- [ ] Tool selection and argument accuracy are scored.
- [ ] Latency and provider-reported or clearly labeled estimated cost are recorded.
- [ ] Repeated stochastic runs include sample count and confidence interval.
- [ ] Mandatory gates override composite scores.
- [ ] Scoring weights and versions are stored with results.
- [ ] A critical regression can reduce the recommended authority level.

## Evidence and audit

- [ ] Each run records scenario, dataset, provider, model, prompt, policy, tool and scoring versions.
- [ ] Proposed and executed actions are distinguishable.
- [ ] Evidence provenance is queryable.
- [ ] Policy input, decision, obligations and explanation are recorded.
- [ ] Audit records form a verifiable hash chain.
- [ ] Tampering with a stored event causes verification to fail.
- [ ] Generated reports disclose limitations and residual risks.

## Quality and supply chain

- [ ] Python linting, formatting and type checking pass.
- [ ] TypeScript linting and type checking pass.
- [ ] Unit, contract, policy, integration and UI tests pass.
- [ ] Secret scanning passes across the current tree and Git history.
- [ ] Static application-security analysis passes or findings are dispositioned.
- [ ] Dependency and container scans pass or findings are dispositioned.
- [ ] Terraform validation passes.
- [ ] An SBOM is generated.
- [ ] Direct dependencies and container images are pinned.
- [ ] Third-party license obligations are documented.

## Documentation and publication

- [ ] README explains the business problem before the technology.
- [ ] Five-minute quick start is verified from a clean environment.
- [ ] Threat model and trust-boundary diagram are current.
- [ ] Provider compatibility matrix distinguishes tested and gateway-supported paths.
- [ ] Policy, scoring, evaluation and custom-adapter guides are complete.
- [ ] Azure deployment is labeled as a reference architecture.
- [ ] `SECURITY.md` includes responsible disclosure.
- [ ] `CONTRIBUTING.md`, code of conduct, issue templates and pull-request template exist.
- [ ] Screenshots and demo assets contain synthetic data only.
- [ ] Public claims pass the evidence review.
- [ ] The owner explicitly approves public publication.

## Release evidence record

Before tagging version 1.0, add a dated record under `docs/releases/` containing:

- commit SHA;
- operating system and tool versions;
- commands executed;
- test summaries;
- scan summaries;
- SBOM path and checksum;
- known limitations;
- residual risks;
- acceptance exceptions; and
- release decision and approver.

