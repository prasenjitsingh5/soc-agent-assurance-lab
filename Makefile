# SOC Agent Assurance Lab
# Every release-blocking local check is reachable from `make verify`.

PY ?= .venv/Scripts/python
ifeq ($(OS),Windows_NT)
PY := .venv/Scripts/python
else
PY := .venv/bin/python
endif
OPA ?= $(shell command -v opa 2>/dev/null || echo tools/opa.exe)
COMPOSE := docker compose -f infrastructure/docker/docker-compose.yml

.PHONY: bootstrap lint format typecheck test policy-test security sbom up down demo verify

bootstrap:
	python -m venv .venv
	$(PY) -m pip install --upgrade pip
	$(PY) -m pip install -e ".[dev,security]"

lint:
	$(PY) -m ruff check .
	$(PY) -m ruff format --check .

format:
	$(PY) -m ruff format .
	$(PY) -m ruff check --fix .

typecheck:
	$(PY) -m mypy

test:
	$(PY) -m pytest --cov --cov-report=term-missing --cov-report=xml

policy-test:
	$(OPA) test policies/rego -v

security:
	$(PY) -m bandit -q -r soclab -c pyproject.toml
	$(PY) -m pip_audit --skip-editable

sbom:
	mkdir -p dist
	$(PY) -m cyclonedx_py environment --output-format json --output-file dist/sbom.cdx.json
	$(PY) -c "import hashlib,sys;print(hashlib.sha256(open('dist/sbom.cdx.json','rb').read()).hexdigest())" > dist/sbom.cdx.json.sha256

up:
	$(COMPOSE) up -d --wait

down:
	$(COMPOSE) down -v

demo:
	$(PY) -m soclab.cli demo

verify: lint typecheck test policy-test
