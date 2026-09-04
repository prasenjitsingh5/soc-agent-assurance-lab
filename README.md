# SOC Agent Assurance Lab

[![ci](https://github.com/prasenjitsingh5/soc-agent-assurance-lab/actions/workflows/ci.yml/badge.svg)](https://github.com/prasenjitsingh5/soc-agent-assurance-lab/actions/workflows/ci.yml)

**Status: under construction. Phase 1 in progress. Not yet released.**

Bring your model. Apply one security policy. Measure control effectiveness. Produce deployment evidence.

The lab answers a question security leaders face before letting an AI agent touch an incident: has this agent, with this model and these controls, earned the authority we are about to give it? It runs a synthetic identity-compromise investigation through a deterministic control plane, attacks it with a fixed adversarial suite, and produces scored, hash-chained evidence behind a deployment recommendation.

## What it contains

| Capability | Status |
|---|---|
| Canonical provider and action contracts | in progress |
| Deterministic SOC simulator with ten tools | planned |
| Bounded investigation orchestrator, mock provider | planned |
| Open Policy Agent authorization, fail closed | planned |
| Control gateway, approvals, isolated executor | planned |
| Provider adapters, fixture tested | planned |
| Hash-chained evidence, tamper tests | planned |
| Adversarial campaigns and assurance scoring | planned |
| Executive and technical reports, CLI, API | planned |
| Local Docker stack | planned |
| Web application | Phase 2 |
| Azure reference architecture | Phase 3 |

See [docs/adr](docs/adr) for the decisions behind the phasing and the [design specification](docs/specs/2026-09-04-soc-agent-assurance-lab-design.md) for the product definition.

## Development

```bash
uv sync --extra dev --extra security   # or: make bootstrap
uv run pytest
make verify
```

Requires [uv](https://docs.astral.sh/uv/) and Python 3.12. Policy tests need the `opa` binary on PATH or in `tools/`. The committed `uv.lock` pins every transitive dependency; CI installs with `uv sync --locked`.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
