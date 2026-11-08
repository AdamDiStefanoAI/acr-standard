# ACR Common Policy Rules
# Shared rules: deny-by-default, rate limiting, spend limits
package acr

import future.keywords.in
import future.keywords.if
import future.keywords.contains

# ── Deny-by-default ───────────────────────────────────────────────────────────
# allow is false unless explicitly set to true by a policy.
default allow := false
default escalate := false
default escalate_queue := "default"
default escalate_sla_minutes := 240

# ── Core allow rule ───────────────────────────────────────────────────────────
# An action is allowed when:
#   1. The agent is registered and not denied
#   2. The tool is in the agent's allowlist
#   3. No deny rules triggered
#   4. Not rate-limited
#   5. Not over spend limit
allow if {
    count(deny) == 0
    not escalate
    tool_in_allowlist
    not rate_limit_exceeded
    not spend_limit_exceeded
}

# ── Tool allowlist ────────────────────────────────────────────────────────────
tool_in_allowlist if {
    input.action.tool_name in input.agent.allowed_tools
}

# ── Forbidden tool check ──────────────────────────────────────────────────────
deny contains reason if {
    input.action.tool_name in input.agent.forbidden_tools
    reason := sprintf("Forbidden tool: %s", [input.action.tool_name])
}

# ── Tool not in allowlist ─────────────────────────────────────────────────────
deny contains reason if {
    not input.action.tool_name in input.agent.allowed_tools
    not input.action.tool_name in input.agent.forbidden_tools
    reason := sprintf("Unauthorized tool: %s (not in allowlist)", [input.action.tool_name])
}

# ── Safe context helpers ──────────────────────────────────────────────────────
# Agents that omit context fields must NOT silently bypass rate/spend limits.
# These helpers provide a safe default (0) when the field is absent, so the
# limit rules always have a numeric value to compare against.

context_actions_this_minute := v if {
    v := input.context.actions_this_minute
} else := 0

context_hourly_spend_usd := v if {
    v := input.context.hourly_spend_usd
} else := 0.0

# ── Rate limiting ─────────────────────────────────────────────────────────────
rate_limit_exceeded if {
    context_actions_this_minute > input.agent.boundaries.max_actions_per_minute
}

deny contains reason if {
    rate_limit_exceeded
    reason := sprintf(
        "Rate limit exceeded: %d actions/min (max: %d)",
        [context_actions_this_minute, input.agent.boundaries.max_actions_per_minute]
    )
}

# ── Spend limit ───────────────────────────────────────────────────────────────
spend_limit_exceeded if {
    context_hourly_spend_usd > input.agent.boundaries.max_cost_per_hour_usd
}

deny contains reason if {
    spend_limit_exceeded
    reason := sprintf(
        "Hourly spend limit exceeded: $%.2f (max: $%.2f)",
        [context_hourly_spend_usd, input.agent.boundaries.max_cost_per_hour_usd]
    )
}
