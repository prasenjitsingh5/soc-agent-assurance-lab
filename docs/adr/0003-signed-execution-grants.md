# ADR 0003: Signed execution grants bind policy decisions to executions

**Status:** Accepted, 2026-09-04

## Context

The design requires that only the isolated executor changes simulated state
and that the orchestrator cannot bypass the control gateway. In a single
process, "cannot bypass" needs a mechanism, not a convention. Anything that
can construct a proposal can also call an executor method unless the executor
demands something only the gateway can produce.

## Decision

The gateway issues an HMAC-SHA256 signed `ExecutionGrant` after the policy
decision, obligations and approval binding succeed. The grant binds:

- the proposal id and a hash of the proposal's incident, tool, arguments and
  identities;
- the policy version that produced the decision;
- the approval id, when one was required;
- the obligations that were fulfilled;
- an issue time and a short expiry (60 seconds by default).

The executor verifies the signature, the expiry, the proposal binding and the
scope, and refuses to honor a grant id twice. Every refusal raises
`AuthorizationError`, which the gateway records as `failed_closed`.

The signing key is shared between the gateway and the executor only. The
orchestrator receives a `ToolProposalPort` and nothing else.

## Consequences

- Tampering with arguments between decision and execution invalidates the
  grant because the hash no longer matches.
- Replaying a grant, reusing a consumed approval or presenting an expired
  approval all fail closed and appear in the gateway event log.
- In the Docker profile the executor runs as a separate container with its
  own copy of the key from the environment, which makes the boundary a
  process boundary as well as a cryptographic one.
- The grant is not a substitute for the audit chain. It proves authorization
  at execution time; the evidence store proves what happened afterwards.
