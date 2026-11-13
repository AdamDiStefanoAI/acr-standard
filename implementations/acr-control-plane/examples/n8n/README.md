# n8n webhook → ACR → synthetic executor

This local example accepts a webhook, asks `/acr/evaluate` to govern a fixed
`create_ticket` action, and returns the decision. Only the gateway calls the
[protected demo executor](../protected_executor/README.md). The workflow has no
payment, email, or ticket-system credentials and never executes a tool itself.
Webhook callers cannot choose the agent identity, tool, or gateway URL.

**Validation status:** the export and boundary assertions are checked by repository
tests. Actual n8n import/execution and the combined Docker stack have **not** been
validated in the implementation environment, which has no Docker executable.
Issue #18 remains open until the live checklist below passes on a disposable host.
Do not treat this as a tested production integration.

## 1. Start a disposable local stack

From `implementations/acr-control-plane/`, follow the [main quickstart](../../README.md#quick-start)
through `.env` creation and operator/service key configuration. Do not reuse
production keys or data. Then, in that same shell:

```bash
export EXECUTOR_HMAC_SECRET="$(python -c 'import secrets; print(secrets.token_hex(32))')"
export EXECUTOR_CREDENTIAL_SECRET="$(python -c 'import secrets; print(secrets.token_hex(32))')"
# Set a specific n8nio/n8n version or digest reviewed for your host, not latest.
export N8N_IMAGE='n8nio/n8n:<your-reviewed-version>'
docker compose -f docker-compose.yml -f examples/n8n/compose.yaml up --build -d
curl --fail http://localhost:8000/acr/health
```

The override supplies matching secrets and service-DNS routing to the gateway
and executor. The executor has no published host port. n8n is exposed only on
loopback port 5678. The base development Compose stack still exposes its other
ports; run on an isolated host. n8n stores its local account and credentials in
`n8n_demo_data`; preserve its encryption key/volume if keeping this environment.

## 2. Register the demo agent and issue its JWT

In the gateway operator console (`http://localhost:8000/console`), authenticate
with the local operator key. Register an **active** agent with:

- ID: `n8n-support-demo`
- Owner: `demo@example.invalid`
- Purpose: `Synthetic customer-support ticket demo`
- Allowed tools: `create_ticket`
- Forbidden tools: `delete_customer`

Issue an agent token using the console, or the operator-authenticated
`POST /acr/agents/n8n-support-demo/token` endpoint. Keep the returned token private;
it expires and must be refreshed/reissued for later demonstrations. Give n8n only
this agent JWT, **not** the operator key or executor secrets.

## 3. Import and configure n8n

Open `http://localhost:5678`, complete n8n's local account setup, and import
[acr_sensitive_action_workflow.json](acr_sensitive_action_workflow.json).
The workflow is deliberately inactive on import. Configure two **different**
Header Auth credentials in n8n:

1. **Agent Webhook:** a random `X-Demo-Key` header, shared only with your local
   test caller. This protects the incoming webhook.
2. **ACR Evaluate:** header name `Authorization`, value `Bearer <agent JWT>`.

The gateway URL is `http://acr-gateway:8000/acr/evaluate`, using Compose service
DNS. `localhost` inside n8n would point to n8n, not the gateway. “Never Error” is enabled only to return gateway DENY (HTTP 403) and
authentication-error bodies to the caller; no downstream execution node exists.
A transport failure still stops the workflow. Never treat a returned body as authorization. Select **Listen for
test event** in the Webhook node, then in another terminal:

```bash
read -rsp 'Webhook demo key: ' DEMO_KEY; echo
curl --fail-with-body http://localhost:5678/webhook-test/acr-sensitive-action \
  -H "X-Demo-Key: $DEMO_KEY" -H 'Content-Type: application/json' \
  -d '{"subject":"Synthetic customer follow-up"}'
unset DEMO_KEY
```

Test webhooks must be armed again for each call. Activate the workflow only if
you need repeated local testing, then use `/webhook/acr-sensitive-action`.
Do not expose it publicly for this demonstration.

## 4. Live acceptance checklist (record results before closing #18)

- Import succeeds on the chosen n8n version; record that exact version.
- An ordinary synthetic request returns `decision=allow` and a nonempty
  `execution_result` from the fake executor. An allow response alone does not
  prove execution: inspect its result and gateway/executor logs.
- Re-arm the test webhook and send `{"subject":"rm -rf /"}` as inert JSON text.
  Under the stock core content-safety policy expect `deny`, with no executor call. Inspect
  logs for the exact run; do not infer absence of execution from HTTP success.
- Missing/wrong webhook key is rejected without calling ACR.
- An expired/wrong agent JWT returns an authentication-error body without calling the executor.
- Confirm the export contains no direct executor node. Disable gateway execution
  and verify that policy permission alone does not produce a fake ticket.

This fixed-ticket example does not demonstrate MODIFY or approval resumption.
The raw gateway response preserves `deny`, `escalate`, reasons, and approval IDs;
returning a response never grants execution authority. A webhook HTTP 200 means
transport succeeded, **not** that ACR allowed the action. Do not attach a direct
sensitive-action node after the response, retry executions blindly, or treat
`escalate` as permission. See the protected-executor limitations concerning
replay, audience, scopes, and authorization binding before any real deployment.

## Static regression check

```bash
pytest tests/test_n8n_example.py -q
```

These tests inspect the exported JSON/configuration, not the n8n runtime. They
cannot establish successful import, node-version compatibility, or live policy
and executor behavior. No live success output is included because none was
observed during implementation.

## Hosted validation route

The dedicated `ACR n8n webhook validation` workflow uses official image
`n8nio/n8n:2.47.5`, imports this same export with disposable credentials, and
sends real authenticated webhooks through the real gateway and OPA to a ledger
wrapper around the real synthetic ticket function. It asserts one ALLOW effect,
zero DENY effects, and webhook authentication rejection. Results are CI evidence,
not a production-readiness claim; the live job must pass before issue #18 closes.
