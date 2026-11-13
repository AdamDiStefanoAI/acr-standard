# Rego policy checks

Run from `implementations/acr-control-plane/` with the Compose-pinned OPA version:

```sh
docker run --rm -v "$PWD/policies:/policies:ro" \
  openpolicyagent/opa:0.70.0 test /policies/ -v
```

Or use the official OPA **0.70.0** binary:

```sh
opa version
opa test policies/ -v
```

Validated on 2026-11-13 using the official Linux amd64 OPA 0.70.0 binary:
**62/62 tests passed**. This runs Rego itself, not a mocked Python policy client.
The Docker equivalent above was not run in that validation environment.

`acr/customer_support_test.rego` contributes eight tests: clean email; separate
synthetic SSN/card email denials; refunds at 100 and 100.01; both billing tools;
and deletion. Each fixture supplies the allowlist, forbidden list, rate/spend
boundaries and context. Dangerous tools are deliberately allowlisted in these
isolated fixtures so assertions prove the customer-support rule denied them,
not an unrelated allowlist check. These tests do not change policy behavior.

Tests use separate packages so fixture data is not included in the gateway's
`data.acr` result. Run the whole directory to load the common and support modules
together and discover both existing content-safety tests and the new tests.

See [the opt-in parameter PII example](examples/README.md) for six additional
checks. It is isolated from the shipped `acr` decision package and does not
silently enable a new production policy.
