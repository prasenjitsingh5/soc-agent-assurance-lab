# Changelog

All notable changes are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Documentation site built with MkDocs and deployed to GitHub Pages; Codespaces dev container with uv and OPA; reproducible social preview and logo generator
- `http` provider: point the lab at any SOC agent over HTTP with the versioned `soclab.agent.v1` contract, published JSON Schema in `schemas/agent-v1/`, fail closed validation and a rule based reference agent in `examples/http_agent/`; `POST /api/v1/campaigns` accepts `provider_id` and `model`
- Campaigns and comparisons run against any registered provider (`--provider`, `--model`); per-stage JSON instructions and tool argument schemas in prompts; native tool calls accepted as plans; Ollama live-validated with llama3.2:3b

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
