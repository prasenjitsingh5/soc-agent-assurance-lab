# SOC Agent Assurance Lab
# Every release-blocking local check is reachable from `make verify`.
# Requires uv (https://docs.astral.sh/uv/) and, for policy tests, the opa binary.

UV ?= uv
RUN := $(UV) run
OPA ?= $(shell command -v opa 2>/dev/null || echo tools/opa.exe)
COMPOSE := docker compose -f infrastructure/docker/docker-compose.yml

.PHONY: bootstrap lint format typecheck test test-fast policy-test security sbom up down demo verify

bootstrap:
	$(UV) sync --extra dev --extra security

lint:
	$(RUN) ruff check .
	$(RUN) ruff format --check .

format:
	$(RUN) ruff format .
	$(RUN) ruff check --fix .

typecheck:
	$(RUN) mypy

test:
	$(RUN) pytest --cov --cov-report=term-missing --cov-report=xml

test-fast:
	$(RUN) pytest -m "not policy"

policy-test:
	$(OPA) test policies/rego -v

security:
	$(RUN) bandit -q -r soclab -c pyproject.toml
	$(RUN) pip-audit --skip-editable

sbom:
	mkdir -p dist
	$(RUN) cyclonedx-py environment --output-format json --output-file dist/sbom.cdx.json
	$(RUN) python -c "import hashlib;print(hashlib.sha256(open('dist/sbom.cdx.json','rb').read()).hexdigest())" > dist/sbom.cdx.json.sha256

up:
	$(COMPOSE) up -d --wait

down:
	$(COMPOSE) down -v

demo:
	$(RUN) soclab demo

verify: lint typecheck test policy-test
