# Parameter PII screening example

`block_pii_params.rego` demonstrates a **pre-execution** check for likely US SSN
and 16-digit credit-card patterns in string values anywhere inside an action's
parameter object, including nested objects and arrays. It applies regardless of
tool name. All fixtures use synthetic data.

This is an **opt-in teaching example**, under
`data.acr_examples.block_pii_params`. Loading this directory does not change the
shipped gateway's `data.acr` decision. The example's `allow` means only that this
one check passed; it is not permission to execute a tool.

From `implementations/acr-control-plane/`, using OPA 0.70.0:

```sh
opa test policies/examples/ -v
# PASS: 6/6 (validated with the official binary on 2026-11-13)
printf '%s' '{"action":{"tool_name":"update_ticket","parameters":{"text":"Order ready"}}}' \
  | opa eval -d policies/examples/block_pii_params.rego --stdin-input \
      'data.acr_examples.block_pii_params.allow'
# true
printf '%s' '{"action":{"tool_name":"update_ticket","parameters":{"nested":[{"text":"Synthetic ID 000-12-3456"}]}}}' \
  | opa eval -d policies/examples/block_pii_params.rego --stdin-input \
      'data.acr_examples.block_pii_params.deny'
# ["Likely SSN pattern in action parameters"]
```

Before adopting it, review your input schema and add a narrowly scoped bridge
from the existing enforcement policy to this example's deny set. Keep all
existing identity, scope, spend, approval and default-deny checks. Do not copy
this example's `allow` into `package acr`, because an additional allow rule could
bypass other controls. Test the combined policy and require a permitted gateway
decision before invoking any downstream side effect. These direct Rego tests do
not prove a deployment enforces that boundary.

Limits: regex screening has false positives and false negatives. It does not
validate SSNs or perform Luhn checks; cover all card lengths; inspect object
keys, numeric values, encoded text, attachments or encrypted data; or establish
comprehensive PII detection or regulatory compliance. Keep identifiers as strings
in an explicit schema. Missing/non-object parameter input is not allowed by this
example. Numeric-value behavior is intentionally documented and tested, rather
than presenting it as comprehensive screening. Never log matched personal data;
these rules return category-only reasons. A real deployment needs additional
schema validation, data classification and policy-specific tests.
