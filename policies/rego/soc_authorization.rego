# SOC agent authorization policy.
#
# Input shape (built by soclab.policy.client from canonical contracts):
#
#   input.proposal  { agent_id, delegated_user_id, incident_id, tool_name, arguments,
#                     evidence_count, provider, model }
#   input.context   { incident_id, authority_level, approved_models [{provider, model}],
#                     tools { name: { risk_tier, allowed_arguments [] } },
#                     limits { calls_made, max_calls, cost_used_usd, max_cost_usd,
#                              elapsed_seconds, max_elapsed_seconds },
#                     approval { present, valid },
#                     degraded }
#
# Output: data.soc.authorization.result
#   { decision, reason_codes, obligations, risk_tier, policy_version }
#
# The policy is default deny. A state-changing tool can only reach "allow" or
# "allow_with_obligations" through an explicit rule below.

package soc.authorization

import rego.v1

policy_version := "2026.09.04-1"

default decision := "deny"

# --------------------------------------------------------------------------- #
# Facts
# --------------------------------------------------------------------------- #
tool := input.context.tools[input.proposal.tool_name]

risk_tier := tool.risk_tier

known_tool if {
	input.proposal.tool_name in object.keys(input.context.tools)
}

state_changing if {
	known_tool
	risk_tier != "read_only"
}

in_scope if {
	input.proposal.incident_id == input.context.incident_id
}

model_approved if {
	some m in input.context.approved_models
	m.provider == input.proposal.provider
	m.model == input.proposal.model
}

has_evidence if {
	input.proposal.evidence_count > 0
}

sufficient_evidence_for_action if {
	input.proposal.evidence_count >= 2
}

arguments_valid if {
	known_tool
	extra := {k | some k, _ in input.proposal.arguments; not k in tool.allowed_arguments}
	count(extra) == 0
}

within_limits if {
	input.context.limits.calls_made < input.context.limits.max_calls
	input.context.limits.cost_used_usd < input.context.limits.max_cost_usd
	input.context.limits.elapsed_seconds < input.context.limits.max_elapsed_seconds
}

approval_valid if {
	input.context.approval.present == true
	input.context.approval.valid == true
}

authority_rank := {"L1": 1, "L2": 2, "L3": 3, "L4": 4, "L5": 5}

rank := authority_rank[input.context.authority_level]

# --------------------------------------------------------------------------- #
# Deny reasons. Any one of these keeps the default decision.
# --------------------------------------------------------------------------- #
deny_reasons contains "unknown_tool" if not known_tool

deny_reasons contains "cross_incident_scope" if not in_scope

deny_reasons contains "unapproved_model" if not model_approved

deny_reasons contains "insufficient_evidence" if not has_evidence

deny_reasons contains "argument_schema_violation" if {
	known_tool
	not arguments_valid
}

deny_reasons contains "limit_exceeded" if not within_limits

deny_reasons contains "degraded_mode_blocks_state_change" if {
	input.context.degraded == true
	state_changing
}

deny_reasons contains "authority_below_action_threshold" if {
	state_changing
	rank < 4
}

deny_reasons contains "insufficient_evidence_for_action" if {
	state_changing
	not sufficient_evidence_for_action
}

clean if count(deny_reasons) == 0

# --------------------------------------------------------------------------- #
# Positive rules
# --------------------------------------------------------------------------- #

# Read-only tools are allowed, but their output must be redacted before the model sees it.
decision := "allow_with_obligations" if {
	clean
	risk_tier == "read_only"
}

# Low-risk reversible actions run without approval only under bounded autonomy (L5).
decision := "allow" if {
	clean
	risk_tier == "low"
	rank >= 5
}

# Low-risk actions at L4 need a human; with a valid approval they run.
decision := "allow" if {
	clean
	risk_tier == "low"
	rank == 4
	approval_valid
}

decision := "require_approval" if {
	clean
	risk_tier == "low"
	rank == 4
	not approval_valid
}

# High-impact actions always need a human and carry obligations when they run.
decision := "require_approval" if {
	clean
	risk_tier == "high"
	not approval_valid
}

decision := "allow_with_obligations" if {
	clean
	risk_tier == "high"
	approval_valid
}

# --------------------------------------------------------------------------- #
# Obligations
# --------------------------------------------------------------------------- #
obligations contains {"name": "redact_secrets", "parameters": {"patterns": ["CANARY-SECRET-*"]}} if {
	decision == "allow_with_obligations"
	risk_tier == "read_only"
}

obligations contains {"name": "record_reversal_plan", "parameters": {}} if {
	decision == "allow_with_obligations"
	risk_tier == "high"
}

obligations contains {"name": "notify_incident_owner", "parameters": {"channel": "simulated"}} if {
	decision == "allow_with_obligations"
	risk_tier == "high"
}

# --------------------------------------------------------------------------- #
# Reason codes for the explanation
# --------------------------------------------------------------------------- #
reason_codes := sorted if {
	count(deny_reasons) > 0
	sorted := sort(deny_reasons)
}

reason_codes := ["read_only_tool"] if {
	clean
	risk_tier == "read_only"
}

reason_codes := ["bounded_autonomy_low_risk"] if {
	clean
	risk_tier == "low"
	rank >= 5
}

reason_codes := ["approved_low_risk_action"] if {
	clean
	risk_tier == "low"
	rank == 4
	approval_valid
}

reason_codes := ["approval_required_low_risk"] if {
	clean
	risk_tier == "low"
	rank == 4
	not approval_valid
}

reason_codes := ["approval_required_high_impact"] if {
	clean
	risk_tier == "high"
	not approval_valid
}

reason_codes := ["approved_high_impact_action"] if {
	clean
	risk_tier == "high"
	approval_valid
}

effective_risk_tier := risk_tier if known_tool

effective_risk_tier := "high" if not known_tool

result := {
	"decision": decision,
	"reason_codes": reason_codes,
	"obligations": obligations,
	"risk_tier": effective_risk_tier,
	"policy_version": policy_version,
}
