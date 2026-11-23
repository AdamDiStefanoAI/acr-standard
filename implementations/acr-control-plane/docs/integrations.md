# Integrations (v1.5.0 WS4)

ACR's two human/machine touchpoints — approval requests and decision
events — can be delivered into the tools an enterprise already runs:
Slack, Microsoft Teams, ServiceNow, and Microsoft Sentinel.

**Architecture rules that hold for every integration:**

- **Chat approvals are clients of the approvals API, never a side
  door.** A chat action is resolved by invoking the pillar 6 approvals
  API handlers with the mapped operator identity. The pending-state
  check, expiry + payload-hash binding (`resumption.check_request`),
  claim-once execution receipts, and execute-on-approve behavior apply
  identically. There is no second decision path.
- **Identity is explicit.** Chat user ids map to operator subjects via
  `SLACK_APPROVER_MAP_JSON` / `TEAMS_APPROVER_MAP_JSON`. An unmapped
  chat user cannot approve anything. The approval record shows both
  identities: `decided_by` is the mapped operator subject;
  `decided_channel` and `chat_actor_id` preserve the transport identity.
- **Inbound callbacks verify signatures before any state change.**
  Unsigned or badly signed callbacks are rejected and change nothing.
- **Delivery is asynchronous and is itself evidence.** Events are
  written to a durable outbox (`integration_outbox`, migration 0020) by
  the producing path — inside a savepoint, so an enqueue failure can
  never break that path — and drained by a worker loop with retry,
  exponential backoff, and dead-lettering. Every attempt is recorded in
  `integration_delivery_attempts`. The evaluate hot path never delivers;
  a failed or down integration cannot block, delay, or alter a
  decision.
- **Secrets live in deployment config only** (environment variables).
  They are never logged and never appear in outbox payloads, messages,
  or evidence.
- **Everything is off by default.** With all integrations disabled, no
  outbox rows are written and behavior is byte-identical to pre-WS4.
  The pre-existing generic approval webhook (`WEBHOOK_URL`,
  HMAC-signed, consumed by the n8n example) is unchanged.

## Verification status — read this first

| Integration | Status |
| --- | --- |
| Slack | Contract-tested against a mocked Slack Web API (`chat.postMessage`, `chat.update`) and fabricated signed callbacks. **Live-workspace verification is an operator smoke step** (checklist below), not something the test suite claims. |
| Microsoft Teams | **UNVERIFIED.** Built to Microsoft's published incoming-webhook / Adaptive Card / outgoing-webhook formats; contract tests against mocks only. Live verification requires a tenant. |
| ServiceNow | **UNVERIFIED.** Table API client contract-tested against mocks only. |
| Microsoft Sentinel | **UNVERIFIED.** Logs Ingestion API shape contract-tested against mocks only. |

## Shared outbox settings

| Setting | Default | Meaning |
| --- | --- | --- |
| `INTEGRATIONS_OUTBOX_POLL_SECONDS` | `5` | Worker drain interval |
| `INTEGRATIONS_OUTBOX_MAX_ATTEMPTS` | `5` | Attempts before dead-letter |
| `INTEGRATIONS_OUTBOX_BACKOFF_BASE_SECONDS` | `30` | Backoff base (doubles per attempt, capped at 1 h) |

Dead-lettered rows keep their last error and full attempt history;
operators inspect them in `integration_outbox` /
`integration_delivery_attempts`. There is no automatic replay of
dead letters in this release — fix the cause, then re-enqueue by
resetting the row's `status` to `pending` and `attempts` to `0`.

## Slack

### What it does

- On approval-required: a Block Kit message with the action summary
  (agent, tool, queue, risk tier, expiry, request + correlation ids)
  and **Approve** / **Deny** buttons is posted to the approvals
  channel. Approval *parameters* are never included — chat is a
  notification surface, not a data surface.
- On a button click: the callback verifies the Slack signature (v0
  scheme, 5-minute timestamp tolerance), maps the Slack user to an
  operator subject, and decides the approval through the approvals
  API. The original message is then updated in place from the
  record's true state (Approved/Denied by whom and when, or Expired).
  Already-decided and expired approvals render as such.
- Containment escalations and kill switch activations post alert
  messages to the alerts channel (falls back to the approvals channel).

### Install (minutes)

1. Create the app from `examples/slack/app-manifest.yaml`
   (api.slack.com/apps → Create New App → From a manifest), after
   replacing `acr.example.com` with your control plane's public base
   URL. The manifest requests one bot scope (`chat:write`) and sets
   the interactivity request URL to
   `https://<your-host>/acr/integrations/slack/actions`.
2. Install the app to the workspace; invite the bot to the approvals
   and alerts channels.
3. Configure the control plane:

   ```bash
   SLACK_ENABLED=true
   SLACK_BOT_TOKEN=xoxb-...          # OAuth & Permissions → Bot User OAuth Token
   SLACK_SIGNING_SECRET=...          # Basic Information → Signing Secret
   SLACK_APPROVALS_CHANNEL=C0123...  # channel ID (right-click channel → View details)
   SLACK_ALERTS_CHANNEL=C0456...     # optional
   SLACK_APPROVER_MAP_JSON={"U0123ABC": "alice@example.com"}
   ```

   The map's values must be operator subjects that hold the
   `approver` role in your operator configuration.

### Operator smoke checklist (live verification)

1. Trigger an approval-required evaluation; confirm the Block Kit
   message appears in the approvals channel with working buttons.
2. As a mapped user, click **Approve**; confirm the message updates to
   show your operator identity and the approval executes per your
   `EXECUTE_ALLOWED_ACTIONS` setting; confirm the execution receipt
   exists via `GET /acr/approvals/{id}/receipt`.
3. Click **Approve** again on a second message for an already-decided
   request (or re-click after deciding via the API); confirm the
   message re-renders to the decided state and no second execution
   occurs.
4. As an *unmapped* user, click a button; confirm nothing is decided.
5. Trigger a containment action (or kill switch activation); confirm
   the alert lands in the alerts channel.
6. Check `integration_delivery_attempts`: every post above has a
   success attempt row.

## Microsoft Teams — UNVERIFIED

- **Approvals + alerts** are posted to `TEAMS_WEBHOOK_URL` (a Teams
  incoming webhook) as Adaptive Cards in the standard
  `application/vnd.microsoft.card.adaptive` message envelope.
- Approve/Deny are `Action.Http` actions posting to
  `{TEAMS_CALLBACK_BASE_URL}/acr/integrations/teams/actions` with a
  per-action signed token (HMAC over request id + action + expiry,
  keyed by `TEAMS_CALLBACK_SECRET`). The callback also accepts the
  Teams outgoing-webhook authentication scheme
  (`Authorization: HMAC <base64>`, keyed by the base64-decoded
  `TEAMS_CALLBACK_SECRET`) for deployments that route actions through
  an outgoing webhook.
- Incoming webhooks cannot edit a posted message, so decisions are
  announced as a follow-up outcome card. The pillar 6 record is the
  source of truth.
- Approver mapping: `TEAMS_APPROVER_MAP_JSON={"<teams-user-id>": "operator-subject"}`.

```bash
TEAMS_ENABLED=true
TEAMS_WEBHOOK_URL=https://<tenant>.webhook.office.com/...
TEAMS_CALLBACK_SECRET=...
TEAMS_CALLBACK_BASE_URL=https://acr.example.com
TEAMS_APPROVER_MAP_JSON={"29:...": "alice@example.com"}
```

## ServiceNow — UNVERIFIED

- Containment events (and kill switch activations) create incidents
  via `POST {SERVICENOW_INSTANCE_URL}/api/now/table/incident` with
  Basic auth from config. Approval denials also create incidents when
  `SERVICENOW_INCIDENT_ON_DENY=true`.
- The ACR correlation id is written to the incident's native
  `correlation_id` field and into the work notes, along with agent,
  action, tier, and deciding identity. The created incident's
  `sys_id`/`number` are stored on the outbox row's `delivery_ref`.

```bash
SERVICENOW_ENABLED=true
SERVICENOW_INSTANCE_URL=https://example.service-now.com
SERVICENOW_USERNAME=acr.integration
SERVICENOW_PASSWORD=...
SERVICENOW_INCIDENT_ON_DENY=false
```

## Microsoft Sentinel — UNVERIFIED

- Recorded policy decisions are exported through the Azure Monitor
  **Logs Ingestion API** (the current documented ingestion path; the
  HTTP Data Collector API is deprecated): an Azure AD
  client-credentials token (scope `https://monitor.azure.com/.default`)
  authorizes
  `POST {SENTINEL_DCE_ENDPOINT}/dataCollectionRules/{SENTINEL_DCR_IMMUTABLE_ID}/streams/{SENTINEL_STREAM_NAME}?api-version=2023-01-01`
  with a JSON array of records (fields: `TimeGenerated`,
  `CorrelationId`, `AgentId`, `PolicyId`, `ToolName`, `Decision`,
  `EnforcementMode`, `Reason`, `Sequence`, `LatencyMs`).
- The stream's custom table (default name `Custom-ACRDecisions_CL`)
  must be created in the workspace with matching columns before
  enabling the export.
- Export rows are enqueued **after** the §18 recording commit, in
  their own guarded transaction, and delivered in batches of up to
  `SENTINEL_BATCH_MAX` (default 100). Export lag or failure never
  touches the evidence trail itself.

```bash
SENTINEL_ENABLED=true
SENTINEL_DCE_ENDPOINT=https://<dce>.<region>.ingest.monitor.azure.com
SENTINEL_DCR_IMMUTABLE_ID=dcr-...
SENTINEL_STREAM_NAME=Custom-ACRDecisions_CL
SENTINEL_TENANT_ID=...
SENTINEL_CLIENT_ID=...
SENTINEL_CLIENT_SECRET=...
```
