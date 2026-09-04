# Policy guide

Authorization lives in one Rego package, `soc.authorization`, in `policies/rego/`. The gateway sends it a small, explicit input document and receives a decision. There is no Python fallback: if OPA cannot answer, state-changing actions fail closed.

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
    "degraded": false
  }
}
```

The gateway builds the context. The model never contributes to it.

## Output

```json
{
  "decision": "require_approval",
  "reason_codes": ["approval_required_high_impact"],
  "obligations": [],
  "risk_tier": "high",
  "policy_version": "2026.09.04-1"
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
2. Add or update a test in `soc_authorization_test.rego`. Run `make policy-test`.
3. Run `uv run pytest tests/contract/test_policy_client.py tests/integration` so the Python side sees the change.
4. Every campaign records the policy version in its evidence chain, so results from before and after the change are distinguishable.
