# ACR Customer Support Agent Policy
# Example policy for the customer-support agent (from the ACR implementation guide)
package acr

import future.keywords.in
import future.keywords.if
import future.keywords.contains

# ── PII detection in email body ───────────────────────────────────────────────
deny contains reason if {
    input.action.tool_name == "send_email"
    body := input.action.parameters.body
    regex.match(`\d{3}-\d{2}-\d{4}`, body)   # SSN pattern
    reason := "PII detected in outbound email: SSN pattern found — redact before sending"
}

deny contains reason if {
    input.action.tool_name == "send_email"
    body := input.action.parameters.body
    regex.match(`\b(?:\d{4}[- ]?){3}\d{4}\b`, body)   # Credit card pattern
    reason := "PII detected in outbound email: credit card pattern found — redact before sending"
}

# ── High-value refund escalation ──────────────────────────────────────────────
# Refunds over $100 require human approval (escalate)
escalate if {
    input.action.tool_name == "issue_refund"
    amount := input.action.parameters.amount
    amount > 100
}

escalate_queue := "finance-approvals" if {
    input.action.tool_name == "issue_refund"
    input.action.parameters.amount > 100
}

escalate_sla_minutes := 240 if {
    input.action.tool_name == "issue_refund"
    input.action.parameters.amount > 100
}

# ── Billing database access denied ───────────────────────────────────────────
deny contains reason if {
    input.action.tool_name in {"query_billing_db", "modify_billing"}
    reason := "Customer support agents do not have billing database access"
}

# ── High-risk action block outside business hours ─────────────────────────────
# (demo rule — in production you would check time.now_ns())
deny contains reason if {
    input.action.tool_name == "delete_customer"
    reason := "Customer deletion is a forbidden operation for support agents"
}
