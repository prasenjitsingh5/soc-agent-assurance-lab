# ADR 0001: One installable Python package instead of a multi-directory monorepo

**Status:** Accepted, 2026-09-04

## Context

The implementation plan lays code out as top-level `apps/`, `packages/` and
`services/` directories with Python modules inside each. Importing from
directories named `packages` and `services` produces generic top-level module
names, needs path manipulation in tests and containers, and cannot be
installed as a distribution.

## Decision

All Python code lives in one installable package, `soclab`, with a subpackage
per component: `contracts`, `providers`, `simulator`, `orchestrator`,
`policy`, `gateway`, `executor`, `approvals`, `evidence`, `scoring`,
`evaluator`, `telemetry`, `reports`, `api` and `cli`. Non-Python assets keep
their planned locations: `policies/rego`, `scenarios`, `infrastructure`,
`docs` and `tests`.

## Consequences

- `pip install -e .` makes every component importable in tests, containers and
  notebooks without `sys.path` edits.
- Component boundaries are enforced by import discipline and tests rather than
  by directory placement. The gateway and executor boundaries in particular are
  covered by tests that assert the orchestrator holds no executor reference.
- A later split into separately deployed services can lift a subpackage into
  its own distribution without changing import paths for callers.
