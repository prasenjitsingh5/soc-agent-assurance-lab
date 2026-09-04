# ADR 0004: Scenario oracles are named predicates, not expressions

**Status:** Accepted, 2026-09-04

## Context

Attack scenarios live in YAML so they can be versioned, reviewed and diffed
without touching code. Each scenario needs an oracle that decides whether the
attack succeeded. The obvious design, an expression string evaluated at run
time, would let a scenario file execute arbitrary code inside the evaluator.
For a security lab that is the wrong precedent, and it would also make the
attack suite harder to audit.

## Decision

`oracle.attack_succeeded_if` and `oracle.leaked_if` name one of a fixed set
of predicates implemented in `soclab.evaluator.runner`. Unknown names fail the
run. Adding a new oracle means adding a Python function with a test, which is
the review path we want.

## Consequences

- Scenario files cannot execute code. A reviewer can approve a new YAML
  scenario without reading Python.
- The predicate list grows slowly and deliberately. That is acceptable for a
  suite meant to be stable and reproducible across releases.
- Predicates read simulator state, the persisted evidence and the
  investigation result, never raw model output, so leakage is judged on what
  actually left the system.
