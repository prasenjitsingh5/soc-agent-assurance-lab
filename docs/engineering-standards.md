# Engineering standards

These are the standing rules for anyone changing this repository. They exist so the assurance claims the lab makes stay true as the code evolves.

## Authoritative documents

- Product design: `docs/specs/2026-09-04-soc-agent-assurance-lab-design.md`
- Implementation plan: `docs/plans/2026-09-04-soc-agent-assurance-lab-implementation.md`
- Acceptance criteria: `docs/PROJECT-ACCEPTANCE.md`
- Research references: `docs/REFERENCE-INVENTORY.md`
- Decisions that deviate from the plan: `docs/adr/`

Read the design and the acceptance criteria before a change of any size.

## Non-negotiable architecture

- Models produce proposals and never execute tools directly.
- The orchestrator cannot bypass the control gateway.
- The policy decision point returns exactly `allow`, `allow_with_obligations`, `require_approval` or `deny`.
- Only the isolated executor, holding a valid signed grant, changes simulated state.
- Every state-changing operation fails closed when policy, approval or evidence dependencies are unavailable.
- Provider payloads are normalized into the canonical Pydantic contracts at the adapter boundary.
- Evidence, decisions, approvals and executions share run, trace and incident identifiers.
- Scoring stays transparent, versioned and reproducible; mandatory gates override the composite.

## Safety

- Synthetic fixtures only. Simulated containment only.
- No offensive payloads, malware or credential theft, ever.
- Canary tokens stand in for secrets in attack scenarios; redact them from logs, traces and reports.
- Never commit `.env`, API keys, access tokens or cloud credentials.
- External deployment and public publication require the owner's explicit approval.

## Method

- Test first: failing test, minimal implementation, passing test, refactor.
- Keep modules focused and interfaces typed; `mypy --strict` must pass.
- Prefer deterministic components for authorization, scoring and fixtures.
- Pin direct dependencies and commit the uv lockfile. Use `uv run` for every command.
- Conventional commits. One task per issue, one pull request per task, CI green before merge.
- Record design deviations as ADRs in `docs/adr/`.

## Required commands

The `Makefile` exposes `bootstrap`, `lint`, `format`, `typecheck`, `test`, `test-fast`, `policy-test`, `security`, `sbom`, `up`, `down`, `demo` and `verify`. `make verify` runs every release-blocking local check.

## Public claims

Use only these labels for capabilities: implemented, simulated, tested, optional integration, reference architecture, planned. Do not describe anything here as production ready, compliant, secure by default or enterprise grade. `tests/docs` enforces this.

## Definition of done

A task is done when its behavior has a test that failed first, the implementation passes it, adjacent tests still pass, documentation is updated and the change is merged through a reviewed pull request. The project is done only when every acceptance item has recorded evidence in `docs/releases/`.
