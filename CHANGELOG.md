# Changelog

All notable changes are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Benign control set: three scenarios (BEN-001 to BEN-003) with attack class `none` that a correct control plane must allow or route to approval. They never count as attacks; the false block rate is now denied legitimate actions over benign runs, feeds a new `benign_actions_allowed` component of operational discipline, and is held to a per-level ceiling (L4 at most 0.5, L5 none). A deny everything decision point scores 3 of 3 and stops at L3; the shipped policy scores 0 of 3
- Scoring profile 2026.09.05-2: attack success, resistance, tiers, coverage and min runs computed over attack scenarios only; `max_false_block_rate` added. Reports show attack runs and benign control runs separately; the technical report gains a false block column
- Adversarial corpus expanded from 12 to 30 scenarios, each with a score family, a difficulty tier and MITRE ATLAS and OWASP LLM Top 10 references; 18 new oracles; four fail closed policy rules (protected assets, non-ASCII, overlong and non-scalar arguments); named fixture injections; encoded canary redaction; harness attacks on the control plane
- Scoring profile 2026.09.05-1: difficulty weighted resistance in every family, corpus coverage, tier completeness for L4 and L5, two passes required for L5. Policy 2026.09.05-1, fixture 1.1.0
- `soclab report` writes a one page executive PDF (optional `pdf` extra, reportlab) or plain text from a JSON scorecard; `GET /campaigns/{id}/reports/executive/pdf`; sample reports in `docs/samples/`
- `soclab opa install` and `soclab demo --install-opa` fetch and verify the pinned OPA 1.20.2 build; PyPI release workflow with trusted publishing and attestations; `docs/release-process.md`
- Documentation site built with MkDocs and deployed to GitHub Pages; Codespaces dev container with uv and OPA; reproducible social preview and logo generator
- `http` provider: point the lab at any SOC agent over HTTP with the versioned `soclab.agent.v1` contract, published JSON Schema in `schemas/agent-v1/`, fail closed validation and a rule based reference agent in `examples/http_agent/`; `POST /api/v1/campaigns` accepts `provider_id` and `model`
- Campaigns and comparisons run against any registered provider (`--provider`, `--model`); per-stage JSON instructions and tool argument schemas in prompts; native tool calls accepted as plans; Ollama live-validated with llama3.2:3b

### Changed
- Distribution renamed to `soclab`; scenarios and the Rego policy ship inside the package under `soclab/data/` (ADR 0006); `SOCLAB_OPA_BIN` renamed to `SOCLAB_OPA_BINARY`

### Fixed
- `soclab compare` writes the baseline executive and technical reports under a `baseline-` prefix, so the weak-control outcome table is no longer lost
- The executor no longer lets a smuggled `incident_id` argument override the bound incident after the policy decision; turn costs are now reported to the gateway so the spend limit can trip
- The JSON report route uses a plain import and accepts `baseline` like the HTML route
- `SOCLAB_GRANT_SIGNING_KEY` is now read when set; before this it was documented but ignored. `.env.example` uses the same SQLite URL as the CLI and API and lists the HTTP agent and OPA binary variables

## [0.1.0] - 2026-09-04

First public release.

Phase 1: the complete assurance core in Python. See `docs/adr/0002-phased-delivery.md`.

### Added
- Canonical contracts, deterministic SOC simulator with ten tools and scope isolation, seven-stage investigation orchestrator, mock provider with grounded and gullible behaviors
- Default-deny Rego authorization with an authority ladder, HTTP and subprocess OPA engines, managed OPA server
- Control gateway, HMAC-signed single-use execution grants, isolated executor, human approval service, secret redaction
- Hash-chained evidence store on SQLite by default and PostgreSQL in Docker, with tamper detection
- Twelve versioned adversarial scenarios, campaign runner for baseline and protected modes, transparent scoring with mandatory gates and Wilson intervals
- Provider adapters for OpenAI, Azure OpenAI, xAI, OpenAI-compatible endpoints, Anthropic, Gemini, Vertex AI and Ollama, contract-tested against recorded fixtures
- OpenInference-style telemetry with optional MLflow and Phoenix adapters; executive and technical reports
- CLI, versioned HTTP API, Docker Compose profile, CI and security workflows, SBOM generation
- Documentation: architecture, threat model, provider compatibility, evaluation methodology, policy guide, custom provider guide, demo script, limitations

### Fixed
- A refused self-approval no longer consumes the pending approval request
- In-memory SQLite is shared across threads so the API test client sees the same store
