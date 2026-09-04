# Repository Instructions for AI Coding Agents

## Purpose

Build a safe, reproducible reference implementation that measures and governs an AI SOC agent's operational authority.

## Authoritative documents

- Product design: `docs/superpowers/specs/2026-09-04-soc-agent-assurance-lab-design.md`
- Implementation plan: `docs/superpowers/plans/2026-09-04-soc-agent-assurance-lab-implementation.md`
- Acceptance criteria: `docs/PROJECT-ACCEPTANCE.md`
- Research references: `docs/REFERENCE-INVENTORY.md`

Read these files completely before implementation.

## Nonnegotiable architecture

- Models produce proposals and never execute tools directly.
- The orchestrator cannot bypass the control gateway.
- The policy decision point returns `allow`, `allow_with_obligations`, `require_approval` or `deny`.
- Only the isolated executor can change simulated state.
- Every state-changing operation fails closed.
- Provider payloads are normalized into canonical Pydantic contracts.
- All evidence, decisions, approvals and executions share trace and incident identifiers.
- Scoring remains transparent, versioned and reproducible.

## Safety

- Use synthetic fixtures only.
- Keep containment actions simulated.
- Never add offensive payload execution, malware or credential theft.
- Store canary tokens instead of secrets in attack scenarios.
- Redact credentials and sensitive values from logs and traces.
- Never commit `.env`, API keys, access tokens or cloud credentials.
- Require explicit approval before any external deployment or public GitHub publication.

## Engineering method

- Use test-driven development.
- Keep modules focused and interfaces typed.
- Favor deterministic components for authorization, scoring and fixtures.
- Pin direct dependencies and commit lockfiles.
- Use conventional commits.
- Keep each plan task independently testable.
- Record design deviations in `docs/adr/`.
- Preserve unrelated changes in a dirty worktree.

## Required commands

The repository-level `Makefile` must expose:

```text
make bootstrap
make lint
make typecheck
make test
make policy-test
make security
make sbom
make up
make down
make demo
make verify
```

`make verify` must run all release-blocking local checks.

## Public claims

Use precise labels:

- implemented
- simulated
- tested
- optional integration
- reference architecture
- planned

Avoid unsupported claims such as production-ready, compliant, unhackable or enterprise-grade.

## Definition of done

A task is complete when its new behavior has a failing test captured first, the implementation passes that test, adjacent tests pass, documentation is updated and the change is committed. The project is complete only when every acceptance item has recorded evidence.

