# ADR 0002: Phased delivery with a complete Python core first

**Status:** Accepted, 2026-09-04

## Context

The design specification describes a React web application, a LangGraph
orchestrator, PostgreSQL and Redis, MLflow and Phoenix adapters, Promptfoo,
Playwright and an Azure Terraform reference in one release. Delivering all of
it before anything is reviewable would leave the repository half-built for a
long time, and a public half-built security project undermines the assurance
message it exists to make.

## Decision

1. **Phase 1** delivers the complete assurance core in Python: canonical
   contracts, the deterministic simulator, the bounded investigation
   orchestrator, the OPA policy decision point, the control gateway and
   isolated executor, hash-chained evidence, adversarial campaigns, scoring,
   provider adapters, telemetry export, executive and technical HTML reports,
   a CLI, a versioned API and the local Docker stack. Phase 1 is the first
   public release.
2. **Phase 2** adds the role-based web application and scenario replay over
   the Phase 1 API.
3. **Phase 3** adds the Azure reference architecture in Terraform.

Three simplifications apply inside Phase 1:

- The orchestrator is an explicit Python state machine behind the planned
  internal port. LangGraph is not a dependency. A security reviewer can read
  the whole state machine in one file, and the port allows a LangGraph
  implementation later without touching callers.
- SQLite is the default evidence store so the quick start and CI need no
  database service. PostgreSQL is used by the Docker profile through the same
  SQLAlchemy models.
- Open Policy Agent remains the only policy decision point. There is no
  in-process fallback; an unreachable OPA fails closed exactly as the design
  requires.

## Consequences

- Every Phase 1 capability is labeled implemented or simulated in the
  documentation. Web views and Azure are labeled planned.
- The acceptance checklist items that depend on the web application and
  Terraform are carried as open items until their phase lands.
