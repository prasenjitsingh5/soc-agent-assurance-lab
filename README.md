# SOC Agent Assurance Lab

[![ci](https://github.com/prasenjitsingh5/soc-agent-assurance-lab/actions/workflows/ci.yml/badge.svg)](https://github.com/prasenjitsingh5/soc-agent-assurance-lab/actions/workflows/ci.yml)
[![security](https://github.com/prasenjitsingh5/soc-agent-assurance-lab/actions/workflows/security.yml/badge.svg)](https://github.com/prasenjitsingh5/soc-agent-assurance-lab/actions/workflows/security.yml)

Before a security team lets an AI agent touch an incident, someone has to decide how much authority it gets. Read-only? Recommend actions? Execute with a human approving each one? Act on its own inside narrow limits? That decision is usually made on a demo and a hunch. This lab replaces the hunch with evidence.

Bring your model. Apply one security policy. Measure control effectiveness. Produce deployment evidence.

## What it does

The lab runs a synthetic identity-compromise investigation through an AI agent twice: once with weak controls and once through a deterministic control plane. Twelve fixed adversarial scenarios attack both runs. Every model turn, tool call, policy decision, approval and execution is written to a hash-chained evidence store, scored against published weights and mandatory safety gates, and rendered into an executive report that leads with one line: the authority level this agent has earned.

With the built-in mock provider and no credentials:

| | Baseline | Protected |
|---|---|---|
| Attacks that succeed | 9 of 12 | 0 of 12 |
| Canary secret reaches evidence | yes | no |
| Recommended authority | L1 Observe | L4 Act with approval |

The same scenarios, controls and scoring run unchanged against OpenAI, Azure OpenAI, Anthropic, Gemini, Vertex AI, xAI, Ollama or any OpenAI-compatible endpoint once credentials are configured.

## The invariant

The model proposes. The control gateway normalizes the proposal and builds the authorization context itself. Open Policy Agent decides allow, allow with obligations, require approval or deny. Only a separate executor, holding a signed single-use grant, changes simulated state. Any outage in that chain fails closed. See [docs/architecture.md](docs/architecture.md) and [docs/threat-model.md](docs/threat-model.md).

## Quick start

Requires Python 3.12, [uv](https://docs.astral.sh/uv/) and the `opa` binary on PATH or in `tools/`.

```bash
git clone https://github.com/prasenjitsingh5/soc-agent-assurance-lab.git
cd soc-agent-assurance-lab
uv sync --extra dev --extra security
uv run soclab compare --out runs/demo
```

Open `runs/demo/executive.html`. Then prove the evidence is intact:

```bash
uv run soclab verify-chain
```

The full walkthrough, including a tamper demonstration, is in [docs/demo-script.md](docs/demo-script.md).

With Docker:

```bash
cp infrastructure/docker/postgres_password.example infrastructure/docker/postgres_password.local
make up
curl http://127.0.0.1:8000/api/v1/scenarios
make down
```

## What is in the box

| Capability | Status |
|---|---|
| Canonical contracts, deterministic SOC simulator with ten tools | implemented, simulated data |
| Seven-stage bounded investigation with evidence-grounded findings | implemented |
| Default-deny Rego authorization with an authority ladder L1 to L5 | implemented, 19 policy tests |
| Control gateway, signed execution grants, human approvals, isolated executor | implemented |
| Hash-chained evidence store with tamper detection | implemented |
| Twelve versioned adversarial scenarios, baseline versus protected campaigns | implemented |
| Five-family scoring, mandatory gates, confidence intervals, authority recommendation | implemented |
| Provider adapters for eight paths | implemented, contract-tested against recorded fixtures |
| OpenInference-style telemetry, MLflow and Phoenix adapters | implemented, optional integration |
| Executive and technical reports, CLI, versioned API | implemented |
| Docker Compose profile with OPA, PostgreSQL, Redis | implemented |
| Role-based web views and scenario replay | planned, Phase 2 |
| Azure reference architecture in Terraform | planned, Phase 3 |

Labels follow [CONTRIBUTING.md](CONTRIBUTING.md): implemented, simulated, tested, optional integration, reference architecture, planned. This project does not claim to be production ready, and [docs/limitations.md](docs/limitations.md) says why.

## Documentation

- [Architecture](docs/architecture.md) and [ADRs](docs/adr)
- [Engineering standards](docs/engineering-standards.md)
- [Threat model](docs/threat-model.md)
- [Evaluation methodology](docs/evaluation-methodology.md)
- [Policy guide](docs/policy-guide.md)
- [Provider compatibility](docs/provider-compatibility.md) and [adding a provider](docs/custom-provider.md)
- [Demo script](docs/demo-script.md)
- [Limitations and known risks](docs/limitations.md)
- [Design specification](docs/specs/2026-09-04-soc-agent-assurance-lab-design.md) and [acceptance checklist](docs/PROJECT-ACCEPTANCE.md)
- [Third-party notices](docs/THIRD-PARTY-NOTICES.md)

## Development

```bash
make bootstrap      # uv sync with dev, security and provider extras
make verify         # ruff, mypy strict, pytest, opa test
make security       # bandit, pip-audit
make sbom           # CycloneDX bill of materials with checksum
```

Every task is an issue, a branch and a pull request that CI must pass. See [CONTRIBUTING.md](CONTRIBUTING.md) and [docs/engineering-standards.md](docs/engineering-standards.md).

## Safety boundaries

No real SIEM, identity, endpoint or network system is ever contacted. All data is synthetic. Containment actions are simulated and return receipts that say so. No offensive tooling is included; the attack scenarios are defensive test cases against a simulated target. See [SECURITY.md](SECURITY.md).

## Disclaimer

This is a personal, independent project, not affiliated with or endorsed by any employer or organization. It is provided as is, without warranty, and is not security, legal or compliance advice. All data is fictional. Third-party names are used only to identify interoperability. Read [DISCLAIMER.md](DISCLAIMER.md) before relying on anything here.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
