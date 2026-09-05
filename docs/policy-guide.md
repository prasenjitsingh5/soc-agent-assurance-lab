# Policy guide

Authorization lives in one Rego package, `soc.authorization`, in `soclab/data/policies/`. The files ship inside the Python package, so an installed wheel evaluates the same Rego that the repository tests. The gateway sends it a small, explicit input document and receives a decision. There is no Python fallback: if OPA cannot answer, state-changing actions fail closed.

## Running OPA

Outside Docker the lab starts its own OPA server from a local binary. It looks for the binary in this order:

1. `SOCLAB_OPA_BINARY`, when it names an existing file.
2. `opa` on `PATH`.
3. The per-user cache written by `soclab opa install`.

`soclab opa install` downloads the pinned build (OPA 1.20.2) for the current operating system and CPU from the official GitHub release, prints the URL and the expected sha256, verifies the file against a digest hard coded in `soclab/policy/opa_binary.py`, and refuses to keep it on any mismatch. Windows, Linux and macOS on amd64 and arm64 are covered. The cache is `%LOCALAPPDATA%\soclab\Cache` on Windows, `~/Library/Caches/soclab` on macOS and `~/.cache/soclab` elsewhere; `SOCLAB_CACHE_DIR` overrides it. Nothing is downloaded unless you run that command or pass `--install-opa` to `soclab demo`. `soclab opa path` prints the binary the lab would use.

Set `SOCLAB_OPA_URL` to use an OPA server that is already running, as the Docker profile does. `SOCLAB_POLICY_DIR` points the managed server and `opa test` at a different policy folder.

## Input

```json
{
  "proposal": {
    "agent_id": "soc-investigator",
    "delegated_user_id": "analyst-1",
    "incident_id": "INC-1001",
    "tool_name": "disable_account",
    "arguments": {"user_id": "u-alex-rivera"},
    "evidence_count": 3,
    "provider": "mock",
    "model": "mock-investigator-v1"
  },
  "context": {
    "incident_id": "INC-1001",
    "authority_level": "L4",
    "approved_models": [{"provider": "mock", "model": "mock-investigator-v1"}],
    "tools": {"disable_account": {"risk_tier": "high", "allowed_arguments": ["user_id"]}},
    "limits": {"calls_made": 6, "max_calls": 40, "cost_used_usd": 0.0, "max_cost_usd": 2.0,
               "elapsed_seconds": 4.2, "max_elapsed_seconds": 300},
    "approval": {"present": false, "valid": false},
    "protected_assets": {"user_ids": ["u-svc-backup"], "endpoint_ids": [], "indicators": ["203.0.113.10", "0.0.0.0/0"]},
    "degraded": false
  }
}
```

The gateway builds the context. The model never contributes to it. The protected-asset lists come from the fixture's `protected_assets` block in campaigns and from `GatewayConfig` elsewhere; when they are missing the policy denies every state change rather than treating nothing as protected.

## Output

```json
{
  "decision": "require_approval",
  "reason_codes": ["approval_required_high_impact"],
  "obligations": [],
  "risk_tier": "high",
  "policy_version": "2026.09.05-1"
}
```

## Deny reasons

| Reason code | Trigger |
|---|---|
| `unknown_tool` | tool not in the registry |
| `cross_incident_scope` | proposal incident differs from the session incident |
| `unapproved_model` | provider and model pair not on the approved list |
| `insufficient_evidence` | no evidence references at all |
| `insufficient_evidence_for_action` | state-changing action with fewer than two references |
| `argument_schema_violation` | argument key not declared for the tool |
| `limit_exceeded` | calls, cost or elapsed time at or over the limit |
| `degraded_mode_blocks_state_change` | policy in degraded mode and the tool changes state |
| `authority_below_action_threshold` | state-changing action below L4 |
| `argument_not_scalar` | an argument value is an object or an array |
| `argument_too_long` | a string argument longer than 512 characters |
| `non_ascii_argument` | a string argument with characters outside printable ASCII, which is how lookalike identifiers arrive |
| `protected_asset` | disable or revoke on a protected user, isolate on a protected endpoint, block on a protected indicator or on any prefix shorter than /8 |
| `protected_assets_undeclared` | state-changing action while the context lacks the three protected-asset lists; the rule fails closed |

All applicable reasons are returned, sorted, so a denied proposal explains every problem at once.

## Obligations

| Obligation | When | Fulfilled by |
|---|---|---|
| `redact_secrets` | every read-only allow | gateway redacts tool output before returning it to the model |
| `record_reversal_plan` | approved high-impact action | gateway records a reversal plan event before execution |
| `notify_incident_owner` | approved high-impact action | gateway records a simulated notification before execution |

An obligation the gateway does not recognize blocks execution.

## Changing the policy

1. Edit the Rego and bump `policy_version`.
2. Add or update a test in `soc_authorization_test.rego`. Run `make policy-test`, which runs `opa test soclab/data/policies -v`.
3. Run `uv run pytest tests/contract/test_policy_client.py tests/integration` so the Python side sees the change.
4. Every campaign records the policy version in its evidence chain, so results from before and after the change are distinguishable.
