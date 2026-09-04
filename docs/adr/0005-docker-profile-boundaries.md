# ADR 0005: Docker profile boundaries

**Status:** Accepted, 2026-09-04

## Context

The design calls for a local Docker Compose profile with the API, OPA,
PostgreSQL and Redis, and for the executor to be isolated from the
orchestrator. Phase 1 ships the assurance core in one Python process; the
process boundary between orchestrator and executor is a Phase 2 concern once
the web application needs a long-running service.

## Decision

The Phase 1 compose profile runs four containers: `api`, `opa`, `postgres` and
`redis`. The API container holds the orchestrator, gateway and executor in one
process, exactly as the CLI does. Authorization still crosses a network
boundary because OPA is a separate container, and evidence crosses one
because PostgreSQL is a separate container.

Hardening applied to every service where the image allows it: pinned tags,
non-root users, read-only root filesystems, tmpfs for scratch paths, memory
limits, health checks, two internal networks (control and data), the API
published on loopback only, and the database password supplied as a Compose
secret from an ignored local file.

Redis is present so the profile matches the design and later background
campaigns have a queue. Phase 1 does not yet use it.

## Consequences

- `make up` gives a reviewer a running API with the real policy engine in
  under a minute without any credentials.
- The smoke test brings the stack up from a clean clone, runs a protected
  campaign through the API and verifies the chain. It skips when Docker is
  not available and runs in CI on the Ubuntu runner.
- Splitting the executor into its own container is tracked for Phase 2 and
  will reuse the signed grant already required by ADR 0003.
