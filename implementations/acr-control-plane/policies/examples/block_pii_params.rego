# Opt-in teaching example, deliberately isolated from the shipped acr package.
package acr_examples.block_pii_params

import future.keywords

default allow := false

# Walk nested objects and arrays; inspect string values, never log their contents.
parameter_strings contains value if {
	walk(input.action.parameters, [_, value])
	is_string(value)
}

# A likely US SSN shape. This is a heuristic, not identity validation.
deny contains "Likely SSN pattern in action parameters" if {
	some value in parameter_strings
	regex.match(`\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b`, value)
}

# A likely 16-digit card shape (optional spaces/hyphens), without Luhn validation.
deny contains "Likely credit-card pattern in action parameters" if {
	some value in parameter_strings
	regex.match(`\b(?:[0-9]{4}[- ]?){3}[0-9]{4}\b`, value)
}

# An explicit object is required. "allow" here ONLY means this PII check passed.
# It must not replace the gateway's identity, scope, spend or approval checks.
allow if {
	is_object(input.action.parameters)
	count(deny) == 0
}
