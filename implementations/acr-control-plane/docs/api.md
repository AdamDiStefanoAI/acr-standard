# ACR Control Plane — API Reference

## Base URL

```
http://localhost:8000
```

Operator console:

```
http://localhost:8000/console
```

The console includes a guided `Policy Studio` workflow that generates a starter
agent manifest and a Rego policy package for common agent types.
It can also save and reload managed policy drafts, publish versioned releases,
activate the live policy bundle alias, and show both the immutable artifact
location and the stable active bundle location for each release.

All responses include:
- `X-Correlation-ID` header — unique request trace ID
- `X-Response-Time-Ms` header — total processing time

Sensitive control-plane endpoints require:
- `X-Operator-API-Key` — operator credential for agent lifecycle, approvals, telemetry, drift, and kill-switch operations
- `Authorization: Bearer <OIDC token>` or an operator SSO browser session when OIDC is enabled

OPA bundle distribution endpoints are intended for internal runtime use and do not require operator authentication:
- `GET /acr/policy-bundles/discovery.json`
- `GET /acr/policy-bundles/active.tar.gz`

Evidence export endpoint:
- `GET /acr/evidence/{correlation_id}`

Downstream executors can require:
- `X-ACR-Execution-Token` — a short-lived gateway-issued authorization token
- `X-ACR-Execution-Signature` — an HMAC signature over the exact JSON body
- `X-ACR-Brokered-Credential` — a short-lived audience/scope credential minted by the gateway
- `X-ACR-Credential-Audience` — the audience value expected by the brokered credential verifier

The helper dependency `acr.gateway.executor_auth.require_gateway_execution` verifies that the token is valid and that it authorizes the exact payload being executed.
The helper dependency `acr.gateway.executor_auth.require_brokered_execution_credential` verifies the downstream credential and its intended audience.

If you are integrating with workflow builders like `n8n`, treat these executor controls as the protected downstream boundary. See [orchestrators.md](orchestrators.md).

---

## Gateway

### POST /acr/evaluate

The main control plane endpoint. All agent action requests flow through here.

**Request:**
```json
{
  "agent_id": "customer-support-01",
  "action": {
    "tool_name": "query_customer_db",
    "parameters": {"customer_id": "C-12345"},
    "description": "Look up customer record"
  },
  "context": {
    "session_id": "sess-abc",
    "actions_this_minute": 5,
    "hourly_spend_usd": 1.20
  },
  "intent": {
    "goal": "Look up customer context before responding",
    "justification": "Support agent needs account details to resolve the case",
    "requested_by_step": "lookup_customer_record",
    "expected_effects": ["read customer record"]
  }
}
```

**Response — allowed (200):**
```json
{
  "decision": "allow",
  "correlation_id": "uuid-v4",
  "policy_decisions": [
    {"policy_id": "acr-allow", "decision": "allow"}
  ],
  "drift_score": 0.12,
  "latency_ms": 47
}
```

**Response — denied (403):**
```json
{
  "decision": "deny",
  "correlation_id": "uuid-v4",
  "reason": "Forbidden tool: delete_customer",
  "policy_decisions": [
    {"policy_id": "acr-deny-0", "decision": "deny", "reason": "Forbidden tool: delete_customer"}
  ]
}
```

**Response — escalated / pending approval (202):**
```json
{
  "decision": "escalate",
  "correlation_id": "uuid-v4",
  "approval_request_id": "apr-uuid",
  "reason": "Refund >$100 requires human approval",
  "approval_queue": "finance-approvals",
  "sla_minutes": 240
}
```

**Error codes:**
| Code | HTTP | Meaning |
|------|------|---------|
| `AGENT_NOT_REGISTERED` | 403 | Agent ID not in registry |
| `AGENT_KILLED` | 403 | Kill switch is active for this agent |
| `POLICY_ENGINE_ERROR` | 503 | OPA unreachable — fail-secure deny |
| `INTERNAL_ERROR` | 500 | Unexpected error — fail-secure deny |

---

## Agent Registry

### POST /acr/agents — Register agent

Requires `X-Operator-API-Key` with `agent_admin`.

**Request:**
```json
{
  "agent_id": "customer-support-01",
  "owner": "support-engineering@example.com",
  "purpose": "Handle customer support tickets",
  "risk_tier": "medium",
  "allowed_tools": ["query_customer_db", "send_email", "create_ticket"],
  "forbidden_tools": ["delete_customer"],
  "data_access": [
    {"resource": "customer_db", "permission": "READ"}
  ],
  "boundaries": {
    "max_actions_per_minute": 30,
    "max_cost_per_hour_usd": 5.0,
    "credential_rotation_days": 90
  }
}
```

**Response (201):** Agent manifest with `created_at` / `updated_at`.

### GET /acr/agents — List all agents

Requires `X-Operator-API-Key` with `agent_admin`, `auditor`, or `security_admin`.

### GET /acr/agents/{agent_id} — Get agent manifest

Requires `X-Operator-API-Key` with `agent_admin`, `auditor`, or `security_admin`.

### PUT /acr/agents/{agent_id} — Update manifest

Requires `X-Operator-API-Key` with `agent_admin`.

Partial updates — only supply fields to change.

### DELETE /acr/agents/{agent_id} — Deregister agent

Requires `X-Operator-API-Key` with `agent_admin` or `security_admin`.

Sets `is_active=false`. Does not delete the record.

### POST /acr/agents/{agent_id}/token — Issue JWT

Requires `X-Operator-API-Key` with `agent_admin`.

**Response:**
```json
{
  "agent_id": "customer-support-01",
  "access_token": "eyJ...",
  "token_type": "bearer",
  "expires_in_seconds": 1800
}
```

---

## Operator Auth

### GET /acr/auth/session

Returns the current operator principal for:
- OIDC browser session
- OIDC bearer token
- operator API key

### GET /acr/auth/oidc/login

Starts the OIDC authorization-code login flow for the operator console.

### GET /acr/auth/oidc/callback

OIDC redirect handler. Exchanges the authorization code for an ID token,
validates it, and creates the signed operator session cookie used by the console.

### POST /acr/auth/logout

Clears the operator session cookie.

---

## Approval Queue

### GET /acr/approvals — List pending approvals

Requires `X-Operator-API-Key` with `approver`, `auditor`, or `security_admin`.

Returns all approvals with `status=pending`, oldest first.

### GET /acr/approvals/{request_id} — Get approval details

Requires `X-Operator-API-Key` with `approver`, `auditor`, or `security_admin`.

### POST /acr/approvals/{request_id}/approve

Requires `X-Operator-API-Key` with `approver` or `security_admin`.

**Request:**
```json
{"decided_by": "ops@example.com", "reason": "Approved after review"}
```

### POST /acr/approvals/{request_id}/deny

Requires `X-Operator-API-Key` with `approver` or `security_admin`.

**Request:**
```json
{"decided_by": "ops@example.com", "reason": "Amount too large"}
```

### POST /acr/approvals/{request_id}/override

Requires `X-Operator-API-Key` with `security_admin`.

Break-glass override. `reason` is required and logged as a security event.

```json
{"decided_by": "security-lead@example.com", "reason": "Emergency override — incident response"}
```

---

## Drift Governance

### GET /acr/drift/{agent_id}

Returns the current drift score and, when present, the governed baseline version currently in force.

### GET /acr/drift/{agent_id}/baseline

Returns the effective baseline profile for the agent.

### GET /acr/drift/{agent_id}/baseline/versions

Lists governed baseline versions for the agent.

### POST /acr/drift/{agent_id}/baseline/propose

Creates a candidate baseline version from recent drift samples.

### POST /acr/drift/{agent_id}/baseline/{baseline_version_id}/approve

Marks a candidate baseline as approved.

### POST /acr/drift/{agent_id}/baseline/{baseline_version_id}/activate

Activates an approved baseline as the current governed baseline.

### POST /acr/drift/{agent_id}/baseline/{baseline_version_id}/reject

Rejects a candidate baseline.

### POST /acr/drift/{agent_id}/baseline/reset

Clears the current computed baseline and emits an audit event.

All baseline governance actions are recorded as `human_intervention` telemetry events so they appear in `/acr/events` and evidence bundles.

---

## Operator Keys

### GET /acr/operator-keys

Requires `X-Operator-API-Key` with `security_admin`.

### POST /acr/operator-keys

Requires `X-Operator-API-Key` with `security_admin`.
Returns the plaintext `api_key` once at creation time.

### POST /acr/operator-keys/{key_id}/rotate

Requires `X-Operator-API-Key` with `security_admin`.
Returns a replacement plaintext `api_key`.

### POST /acr/operator-keys/{key_id}/revoke

Requires `X-Operator-API-Key` with `security_admin`.

---

## Policy Drafts

### GET /acr/policy-drafts

Requires `X-Operator-API-Key` with `agent_admin`, `security_admin`, or `auditor`.

### GET /acr/policy-drafts/{draft_id}

Requires `X-Operator-API-Key` with `agent_admin`, `security_admin`, or `auditor`.

### POST /acr/policy-drafts

Requires `X-Operator-API-Key` with `agent_admin` or `security_admin`.

### PUT /acr/policy-drafts/{draft_id}

Requires `X-Operator-API-Key` with `agent_admin` or `security_admin`.

### GET /acr/policy-drafts/{draft_id}/bundle

Requires `X-Operator-API-Key` with `agent_admin`, `security_admin`, or `auditor`.
Returns publishable filenames and contents for the draft manifest and Rego policy.

### POST /acr/policy-drafts/{draft_id}/simulate

Requires `X-Operator-API-Key` with `agent_admin`, `security_admin`, or `auditor`.
Simulates the saved draft against a sample action and context.

### GET /acr/policy-drafts/{draft_id}/validate

Requires `X-Operator-API-Key` with `agent_admin`, `security_admin`, or `auditor`.
Validates the draft before publication.

### POST /acr/policy-drafts/{draft_id}/publish

Requires `X-Operator-API-Key` with `security_admin`.
Publishes the draft as a new versioned policy release.
The release response includes artifact URI, SHA-256, publish backend metadata,
and activation status (`inactive` until explicitly activated).

### GET /acr/policy-drafts/releases/history

Requires `X-Operator-API-Key` with `agent_admin`, `security_admin`, or `auditor`.
Returns release history across all published policy releases.

### POST /acr/policy-drafts/releases/{release_id}/activate

Requires `X-Operator-API-Key` with `security_admin`.
Marks a published release as the active release for its agent and writes the
stable bundle alias OPA should poll:

- local backend: `<POLICY_BUNDLE_LOCAL_DIR>/<agent_id>/active/current.tar.gz`
- S3 backend: `s3://<bucket>/<prefix>/<agent_id>/active/current.tar.gz`

The response includes `active_bundle_uri`, `activated_by`, and `activated_at`.

### POST /acr/policy-drafts/releases/{release_id}/rollback

Requires `X-Operator-API-Key` with `security_admin`.
Creates a new release by rolling back to the selected prior release.

## Policy Bundles

### GET /acr/policy-bundles/discovery.json

Returns an OPA-compatible discovery document pointing at the aggregate active runtime bundle.
Use this as the single OPA entrypoint in production.

### GET /acr/policy-bundles/active.tar.gz

Returns a tar.gz bundle containing:
- shared `common.rego`
- shared `content_safety.rego` (default content-level guardrails: destructive
  shell commands, path traversal, base64-encoded destructive payloads)
- all currently activated agent policy releases, scoped to their `agent_id`
- bundle metadata listing the active releases

Response headers:
- `X-Policy-Bundle-Sha256` — SHA-256 checksum of the generated bundle

---

## Observability

### GET /acr/health

```json
{"status": "healthy", "version": "1.0", "env": "development"}
```

### GET /acr/live

Liveness probe for orchestrators.

### GET /acr/ready

Readiness probe. Returns dependency status for PostgreSQL, Redis, and OPA.

### GET /acr/events

Requires `X-Operator-API-Key` with `auditor`, `agent_admin`, or `security_admin`.

Query parameters:
- `agent_id` — filter by agent
- `event_type` — `ai_inference | policy_decision | drift_alert | containment_action | human_intervention`
- `limit` — max results (default 50)

Returns array of full telemetry event objects.

### GET /acr/events/{correlation_id}

Requires `X-Operator-API-Key` with `auditor`, `agent_admin`, or `security_admin`.

Returns all events sharing a correlation ID, in chronological order. Use this to reconstruct the full trace of a request.

### GET /acr/evidence/{correlation_id}

Requires operator authentication with `auditor`, `agent_admin`, or `security_admin`.

Exports a per-run evidence ZIP containing:
- `manifest.json`
- `events.jsonl`
- `checksums.sha256`

Response headers:
- `X-Evidence-Bundle-Sha256` — SHA-256 checksum of the ZIP archive

---

## Drift Detection

### GET /acr/drift/{agent_id}

Requires `X-Operator-API-Key` with `auditor`, `agent_admin`, or `security_admin`.

Returns current drift score and signal breakdown:
```json
{
  "agent_id": "customer-support-01",
  "score": 0.23,
  "signals": [
    {
      "name": "denial_rate",
      "current_value": 0.15,
      "baseline_mean": 0.02,
      "baseline_std": 0.01,
      "z_score": 13.0,
      "weight": 0.35,
      "normalized_contribution": 0.35
    }
  ],
  "sample_count": 847,
  "is_baseline_ready": true
}
```

### GET /acr/drift/{agent_id}/baseline

Requires `X-Operator-API-Key` with `auditor`, `agent_admin`, or `security_admin`.

Returns the stored baseline profile used for drift comparison.

### POST /acr/drift/{agent_id}/baseline/reset

Requires `X-Operator-API-Key` with `agent_admin` or `security_admin`.

Resets baseline — clears stored statistics and restarts collection from scratch.

---

## Kill Switch (port 8443)

The kill switch runs as an independent service. Control endpoints require both `X-Killswitch-Secret` and `X-Operator-API-Key`.

### POST /acr/kill

```json
{"agent_id": "customer-support-01", "reason": "Anomalous behaviour detected", "operator_id": "security-team"}
```

### POST /acr/kill/restore

```json
{"agent_id": "customer-support-01", "operator_id": "security-team"}
```

### GET /acr/kill/status/{agent_id}

```json
{
  "agent_id": "customer-support-01",
  "is_killed": true,
  "reason": "Anomalous behaviour detected",
  "killed_at": "2026-03-16T14:30:00+00:00",
  "killed_by": "security-team"
}
```

### GET /acr/kill/status — List all kill switch states
