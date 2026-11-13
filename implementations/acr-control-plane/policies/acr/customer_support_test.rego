# Direct regression tests for the shipped customer-support policy.
# A separate test package keeps fixtures out of the gateway's data.acr query.
package acr_customer_support_test

import future.keywords

fixture(tool, parameters) := {
	"action": {"tool_name": tool, "parameters": parameters},
	"agent": {
		"allowed_tools": ["send_email", "issue_refund", "query_billing_db", "modify_billing", "delete_customer"],
		"forbidden_tools": [],
		"boundaries": {"max_actions_per_minute": 30, "max_cost_per_hour_usd": 5},
	},
	"context": {"actions_this_minute": 0, "hourly_spend_usd": 0},
}

test_clean_email_allowed if {
	result := data.acr with input as fixture("send_email", {"body": "Your order is ready."})
	result.allow
	not result.escalate
	count(result.deny) == 0
}

test_refund_at_boundary_allowed if {
	result := data.acr with input as fixture("issue_refund", {"amount": 100})
	result.allow
	not result.escalate
	count(result.deny) == 0
}

test_refund_above_boundary_escalated if {
	result := data.acr with input as fixture("issue_refund", {"amount": 100.01})
	not result.allow
	result.escalate
	result.escalate_queue == "finance-approvals"
	result.escalate_sla_minutes == 240
	count(result.deny) == 0
}

test_ssn_email_denied if {
	result := data.acr with input as fixture("send_email", {"body": "Synthetic ID 000-12-3456"})
	result.deny == {"PII detected in outbound email: SSN pattern found — redact before sending"}
	not result.allow
	not result.escalate
}

test_card_email_denied if {
	result := data.acr with input as fixture("send_email", {"body": "Synthetic card 4111 1111 1111 1111"})
	result.deny == {"PII detected in outbound email: credit card pattern found — redact before sending"}
	not result.allow
	not result.escalate
}

test_billing_query_denied if {
	result := data.acr with input as fixture("query_billing_db", {})
	result.deny == {"Customer support agents do not have billing database access"}
	not result.allow
	not result.escalate
}

test_billing_write_denied if {
	result := data.acr with input as fixture("modify_billing", {})
	result.deny == {"Customer support agents do not have billing database access"}
	not result.allow
	not result.escalate
}

test_customer_deletion_denied if {
	result := data.acr with input as fixture("delete_customer", {})
	result.deny == {"Customer deletion is a forbidden operation for support agents"}
	not result.allow
	not result.escalate
}
