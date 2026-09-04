# Contributing

Thank you for looking. This is a personal reference implementation with a narrow purpose, so contributions that sharpen the assurance measurement are more welcome than ones that widen the feature set.

## Ground rules

The full set of standing rules is in [docs/engineering-standards.md](docs/engineering-standards.md). The ones that matter most:

- **Synthetic only.** No real logs, records, credentials or personal data, ever. Fixtures use documentation address ranges and invented names.
- **Simulated actions only.** Nothing may connect to a real SIEM, identity, endpoint or network system.
- **The invariant holds.** The model proposes, the gateway normalizes, OPA decides, the executor acts. A change that lets a proposal skip any of those steps will not be merged.
- **Fail closed.** Any new state-changing path must fail closed when policy, approval or evidence dependencies are unavailable.
- **Honest labels.** Documentation uses implemented, simulated, tested, optional integration, reference architecture or planned. Avoid production-ready, compliant, secure or enterprise-grade.

## Workflow

1. Open an issue describing the change and which acceptance item in `docs/PROJECT-ACCEPTANCE.md` it serves.
2. Branch from `main`. One change per pull request.
3. Write the failing test first, then the code. `make verify` must pass: ruff, mypy strict, pytest, and the Rego tests.
4. Record any design deviation as an ADR in `docs/adr/`.
5. Use conventional commit messages: `feat:`, `fix:`, `chore:`, `docs:`, `test:`.
6. Pull requests are squash-merged after CI passes.

## Setup

```bash
uv sync --extra dev --extra security --extra providers
make verify
```

The `opa` binary is required for policy tests. Docker is optional and only needed for the smoke test.

## Adding an attack scenario

Add a YAML file under `scenarios/attacks/` with a new id, a version, an attack class, the untrusted payload location, the expected control and an oracle predicate. If the predicate does not exist, add it to `soclab/evaluator/runner.py` with a test. Scenario files never contain code (ADR 0004).

## Adding a provider

See `docs/custom-provider.md`. Contract tests against recorded, sanitized fixtures are required; a live run is optional and recorded separately.
