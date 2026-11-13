package acr_examples_block_pii_params_test

import future.keywords

check(params) := result if {
	result := data.acr_examples.block_pii_params with input as {"action": {"tool_name": "update_ticket", "parameters": params}}
}

test_clean_parameters_allowed if {
	result := check({"message": "Order ready", "nested": ["Hello", 42]})
	result.allow
	count(result.deny) == 0
}

test_nested_ssn_denied if {
	result := check({"nested": [{"message": "Synthetic ID 000-12-3456"}]})
	not result.allow
	result.deny == {"Likely SSN pattern in action parameters"}
}

test_nested_card_denied if {
	result := check({"nested": ["Synthetic card 4111-1111-1111-1111"]})
	not result.allow
	result.deny == {"Likely credit-card pattern in action parameters"}
}

test_numeric_parameters_not_treated_as_strings if {
	result := check({"amount": 42})
	result.allow
}

test_missing_parameters_not_allowed if {
	not data.acr_examples.block_pii_params.allow with input as {"action": {"tool_name": "update_ticket"}}
}

test_nonobject_parameters_not_allowed if {
	result := check("not an object")
	not result.allow
}
