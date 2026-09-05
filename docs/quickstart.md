# Quickstart

Three ways to get a first result. All of them use the built-in mock provider and synthetic data. No credentials are needed.

## Option A: GitHub Codespaces

Open the repository on GitHub, choose Code, then Codespaces, then create a codespace on `main`. The dev container installs uv, the project with every extra and the `opa` binary, then verifies the OPA checksum. When the terminal appears:

```bash
uv run soclab compare --out runs/demo
```

Details are in `.devcontainer/README.md` in the repository.

## Option B: Local install

Requires Python 3.12, [uv](https://docs.astral.sh/uv/) and the `opa` binary (version 1.20.2 is what CI uses) on PATH or in `tools/`.

```bash
git clone https://github.com/prasenjitsingh5/soc-agent-assurance-lab.git
cd soc-agent-assurance-lab
uv sync --extra dev --extra security
uv run soclab compare --out runs/demo
```

Open `runs/demo/executive.html`. Then check that the evidence chain is intact:

```bash
uv run soclab verify-chain
```

## Option C: Docker Compose

Starts the API, OPA, PostgreSQL and Redis as a local profile.

```bash
cp infrastructure/docker/postgres_password.example infrastructure/docker/postgres_password.local
make up
curl http://127.0.0.1:8000/api/v1/scenarios
make down
```

## What you should see

With the mock provider the comparison is deterministic:

| | Baseline | Protected |
|---|---|---|
| Attacks that succeed | 9 of 12 | 0 of 12 |
| Canary secret reaches evidence | yes | no |
| Recommended authority | L1 Observe | L4 Act with approval |

The [demo script](demo-script.md) explains each step, including how to tamper with the evidence store and watch verification fail.

## Bring your own model

Set the provider's environment variable and pick it on the command line:

```bash
export OPENAI_API_KEY=...
uv run soclab investigate --provider openai --mode protected
```

The registry refuses providers that are not configured or not approved. [Provider compatibility](provider-compatibility.md) lists what each adapter supports. [Custom provider](custom-provider.md) shows how to add one.

## Development checks

```bash
make verify     # ruff, mypy strict, pytest, opa test
make security   # bandit, pip-audit
```

The [engineering standards](engineering-standards.md) describe what every change must satisfy.
