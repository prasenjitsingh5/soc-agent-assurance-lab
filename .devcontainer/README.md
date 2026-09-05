# Dev container

One click path through GitHub Codespaces:

1. Open https://github.com/prasenjitsingh5/soc-agent-assurance-lab.
2. Choose Code, then the Codespaces tab, then "Create codespace on main".
3. Wait for `post-create.sh` to finish. It installs uv 0.12.9, runs `uv sync --all-extras`, downloads OPA 1.20.2 for Linux amd64 and checks its sha256 against the value published on the release page. A checksum mismatch stops the build.
4. In the terminal:

```bash
uv run soclab compare --out runs/demo
uv run soclab verify-chain
```

Open `runs/demo/executive.html` from the file explorer.

## What is inside

| Item | Value |
|---|---|
| Image | `python:3.12.14-bookworm`, the official Python image, pinned by tag |
| Package manager | uv 0.12.9, the same version CI uses |
| Policy engine | OPA v1.20.2 at `/usr/local/bin/opa`, exported as `SOCLAB_OPA_BINARY` |
| Forwarded port | 8000, for `uv run uvicorn soclab.api.main:app --host 0.0.0.0 --port 8000` |
| Editor extensions | Python, Ruff, Open Policy Agent |

## Running the checks

```bash
make verify     # ruff, mypy strict, pytest, opa test
make security   # bandit, pip-audit
uv run mkdocs serve --dev-addr 0.0.0.0:8000   # documentation preview on port 8000
```

## Local use

The same configuration works with the VS Code Dev Containers extension: open the repository folder and choose "Reopen in Container". Docker Compose is not started by the dev container; run `make up` yourself if you want the API, OPA, PostgreSQL and Redis profile.
