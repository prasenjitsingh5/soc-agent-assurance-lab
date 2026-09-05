package soc.authorization_test

import rego.v1

import data.soc.authorization

tools := {
	"get_identity_profile": {"risk_tier": "read_only", "allowed_arguments": ["user_id"]},
	"search_siem_events": {"risk_tier": "read_only", "allowed_arguments": ["query"]},
	"revoke_sessions": {"risk_tier": "low", "allowed_arguments": ["user_id"]},
	"disable_account": {"risk_tier": "high", "allowed_arguments": ["user_id"]},
}

base_context := {
	"incident_id": "INC-1001",
	"authority_level": "L4",
	"approved_models": [{"provider": "mock", "model": "mock-investigator-v1"}],
	"tools": tools,
	"limits": {
		"calls_made": 3,
		"max_calls": 50,
		"cost_used_usd": 0.01,
		"max_cost_usd": 5,
		"elapsed_seconds": 10,
		"max_elapsed_seconds": 600,
	},
	"approval": {"present": false, "valid": false},
	"degraded": false,
}

base_proposal := {
	"agent_id": "soc-investigator",
	"delegated_user_id": "analyst-1",
	"incident_id": "INC-1001",
	"tool_name": "get_identity_profile",
	"arguments": {"user_id": "u-alex-rivera"},
	"evidence_count": 3,
	"provider": "mock",
	"model": "mock-investigator-v1",
}

with_proposal(overrides) := object.union(base_proposal, overrides)

with_context(overrides) := object.union(base_context, overrides)

# --------------------------------------------------------------------------- read-only
test_read_only_allowed_with_redaction if {
	r := authorization.result with input as {"proposal": base_proposal, "context": base_context}
	r.decision == "allow_with_obligations"
	r.reason_codes == ["read_only_tool"]
	count(r.obligations) == 1
	some o in r.obligations
	o.name == "redact_secrets"
	r.risk_tier == "read_only"
}

test_read_only_allowed_at_l1 if {
	r := authorization.result with input as {
		"proposal": base_proposal,
		"context": with_context({"authority_level": "L1"}),
	}
	r.decision == "allow_with_obligations"
}

# --------------------------------------------------------------------------- denials
test_default_is_deny_on_empty_input if {
	r := authorization.result with input as {"proposal": {}, "context": {}}
	r.decision == "deny"
}

test_cross_incident_denied if {
	r := authorization.result with input as {
		"proposal": with_proposal({"incident_id": "INC-OTHER"}),
		"context": base_context,
	}
	r.decision == "deny"
	"cross_incident_scope" in r.reason_codes
}

test_unknown_tool_denied if {
	r := authorization.result with input as {
		"proposal": with_proposal({"tool_name": "drop_database"}),
		"context": base_context,
	}
	r.decision == "deny"
	"unknown_tool" in r.reason_codes
	r.risk_tier == "high"
}

test_insufficient_evidence_denied if {
	r := authorization.result with input as {
		"proposal": with_proposal({"evidence_count": 0}),
		"context": base_context,
	}
	r.decision == "deny"
	"insufficient_evidence" in r.reason_codes
}

test_unapproved_model_denied if {
	r := authorization.result with input as {
		"proposal": with_proposal({"model": "mock-cheap-v0"}),
		"context": base_context,
	}
	r.decision == "deny"
	"unapproved_model" in r.reason_codes
}

test_argument_schema_violation_denied if {
	r := authorization.result with input as {
		"proposal": with_proposal({"arguments": {"user_id": "u-alex-rivera", "force": true}}),
		"context": base_context,
	}
	r.decision == "deny"
	"argument_schema_violation" in r.reason_codes
}

test_limit_exceeded_denied if {
	r := authorization.result with input as {
		"proposal": base_proposal,
		"context": with_context({"limits": object.union(base_context.limits, {"calls_made": 50})}),
	}
	r.decision == "deny"
	"limit_exceeded" in r.reason_codes
}

test_degraded_mode_blocks_state_change_but_not_reads if {
	blocked := authorization.result with input as {
		"proposal": with_proposal({"tool_name": "revoke_sessions"}),
		"context": with_context({"degraded": true, "authority_level": "L5"}),
	}
	blocked.decision == "deny"
	"degraded_mode_blocks_state_change" in blocked.reason_codes

	allowed := authorization.result with input as {
		"proposal": base_proposal,
		"context": with_context({"degraded": true}),
	}
	allowed.decision == "allow_with_obligations"
}

# --------------------------------------------------------------------------- authority ladder
test_state_change_denied_below_l4 if {
	r := authorization.result with input as {
		"proposal": with_proposal({"tool_name": "revoke_sessions"}),
		"context": with_context({"authority_level": "L3"}),
	}
	r.decision == "deny"
	"authority_below_action_threshold" in r.reason_codes
}

test_low_risk_requires_approval_at_l4 if {
	r := authorization.result with input as {
		"proposal": with_proposal({"tool_name": "revoke_sessions"}),
		"context": base_context,
	}
	r.decision == "require_approval"
	r.reason_codes == ["approval_required_low_risk"]
	count(r.obligations) == 0
}

test_low_risk_allowed_at_l4_with_approval if {
	r := authorization.result with input as {
		"proposal": with_proposal({"tool_name": "revoke_sessions"}),
		"context": with_context({"approval": {"present": true, "valid": true}}),
	}
	r.decision == "allow"
	r.reason_codes == ["approved_low_risk_action"]
}

test_low_risk_allowed_at_l5_without_approval if {
	r := authorization.result with input as {
		"proposal": with_proposal({"tool_name": "revoke_sessions"}),
		"context": with_context({"authority_level": "L5"}),
	}
	r.decision == "allow"
	r.reason_codes == ["bounded_autonomy_low_risk"]
}

test_high_risk_requires_approval_even_at_l5 if {
	r := authorization.result with input as {
		"proposal": with_proposal({"tool_name": "disable_account"}),
		"context": with_context({"authority_level": "L5"}),
	}
	r.decision == "require_approval"
	r.reason_codes == ["approval_required_high_impact"]
}

test_high_risk_with_approval_carries_obligations if {
	r := authorization.result with input as {
		"proposal": with_proposal({"tool_name": "disable_account"}),
		"context": with_context({"approval": {"present": true, "valid": true}}),
	}
	r.decision == "allow_with_obligations"
	names := {o.name | some o in r.obligations}
	names == {"record_reversal_plan", "notify_incident_owner"}
}

test_expired_approval_does_not_unlock if {
	r := authorization.result with input as {
		"proposal": with_proposal({"tool_name": "disable_account"}),
		"context": with_context({"approval": {"present": true, "valid": false}}),
	}
	r.decision == "require_approval"
}

test_state_change_needs_two_pieces_of_evidence if {
	r := authorization.result with input as {
		"proposal": with_proposal({"tool_name": "revoke_sessions", "evidence_count": 1}),
		"context": with_context({"authority_level": "L5"}),
	}
	r.decision == "deny"
	"insufficient_evidence_for_action" in r.reason_codes
}

test_multiple_denials_are_all_reported if {
	r := authorization.result with input as {
		"proposal": with_proposal({"tool_name": "disable_account", "incident_id": "INC-9", "model": "x"}),
		"context": with_context({"authority_level": "L2"}),
	}
	r.decision == "deny"
	r.reason_codes == ["authority_below_action_threshold", "cross_incident_scope", "unapproved_model"]
}
