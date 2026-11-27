# ACR Telemetry Schema Specification

**Version:** 1.0  
**Status:** Stable  
**Last Updated:** March 2026

This document describes a telemetry field layout for ACR implementations. The normative v1.0.1 PDF §§11 and 18 govern required evidence and failure handling; see [source precedence and versions](../README.md#normative-source-and-document-versions). The schema version `1.0` identifies the format, not the normative PDF or software release. This guide does not assert that every reference-implementation event already satisfies these requirements. It supports [Pillar 4: Execution Observability](../pillars/04-execution-observability.md), audit trails, drift detection input, and compliance evidence generation.

## Purpose and Scope

- **Purpose:** Provide a consistent, machine-readable structure for all runtime events related to AI system actions, policy decisions, drift alerts, containment actions, and human interventions.
- **Scope:** Events emitted by the ACR control plane (or equivalent governance layer) during request processing. Out of scope: model training telemetry, pre-deployment validation logs, and non-ACR application logs.
- **Consumers:** Observability pipelines, audit stores, drift detection services, compliance reporting, and incident response tooling.

## Event Types

Every event MUST include an `event_type` from the following set:

| event_type | Description |
|------------|-------------|
| `ai_inference` | Standard model invocation (request → policy checks → model/tools → response) |
| `policy_decision` | Policy evaluation without inference (e.g. pre-flight check, re-validation) |
| `drift_alert` | Anomaly or drift detection event (behavioral baseline deviation) |
| `containment_action` | Automated or manual containment response (throttle, restrict, isolate, kill) |
| `human_intervention` | Manual override, approval, or break-glass action |

## Schema Overview

Events are JSON objects. Field names use `snake_case`. Timestamps use ISO 8601 with timezone (e.g. `2026-03-16T14:22:01Z`). All UUIDs are RFC 4122 version 4 where applicable.

### Top-Level Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `acr_version` | string | Yes | ACR schema version (e.g. `"1.0"`). Semantic versioning for backward compatibility. |
| `event_id` | string | Yes | Unique event identifier (UUID v4 recommended). |
| `event_type` | string | Yes | One of: `ai_inference`, `policy_decision`, `drift_alert`, `containment_action`, `human_intervention`. |
| `timestamp` | string | Yes | ISO 8601 timestamp with timezone. |
| `correlation_id` | string | Conditional | A request or correlation identifier is required for every ACR action/decision record. This field or equivalent linkage MUST connect the full action chain. |
| `agent` | object | Yes | Agent identity and purpose for required ACR action/decision records. Supplemental system-health events do not replace these records. |
| `request` | object | Conditional | Request context; request or correlation identifier MUST be present. |
| `execution` | object | Conditional | Execution metadata MUST be present for execution events. |
| `policies` | array | Yes | Relevant policy results for required ACR action/decision records. |
| `decision` | string | Yes | Decision outcome: `allow`, `deny`, `modify`, or `escalate`. |
| `approval` | object | Conditional | Approval metadata MUST be present for approval or escalation events. |
| `output` | object | No | Output metadata (tokens, cost); for inference events. |
| `metadata` | object | No | Environment, drift score, and other extensible attributes. |

### Object: `agent`

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `agent_id` | string | Yes | Stable identifier for the AI system or agent instance. |
| `purpose` | string | Yes | Operational purpose or scope (e.g. `customer_support`, `data_analysis`). |
| `model` | object | No | Model identifier and optional version/vendor. |
| `risk_tier` | string | No | Risk classification if defined (e.g. `low`, `medium`, `high`). |

### Object: `request`

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `request_id` | string | Conditional | Required if a correlation identifier is not recorded elsewhere; full action-chain linkage is still required. |
| `input` | object | No | Sanitized or summarized input (avoid logging full PII); size limits apply. |

### Object: `execution`

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `duration_ms` | number | No | End-to-end duration in milliseconds. |
| `tool_calls` | array | No | List of tool invocations (name, params summary, result summary). |
| `error` | string | No | Error message or code if the execution failed. |
| `outcome` | string | Conditional | Outcome of the executed effect, required for execution events that ended in failure or timeout: `completed`, `cancelled_before_dispatch`, or `dispatched_unknown`. An effect whose outcome cannot be confirmed MUST use `dispatched_unknown`. |

### Object: `policies[]`

Each element represents one policy evaluation:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `policy_id` | string | Yes | Policy or rule identifier. |
| `decision` | string | Yes | `allow`, `deny`, `modify`, or `escalate`. |
| `rule_id` | string | No | Specific rule that fired. |
| `transformations` | number | No | Count of transformations applied (e.g. redactions). |

### Object: `output`

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `tokens` | object | No | Input/output token counts if available. |
| `cost` | object | No | Cost or usage metadata if available. |
| `redacted` | boolean | No | Whether output was redacted or truncated for logging. |

### Object: `metadata`

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `environment` | string | No | Deployment or environment label (e.g. `production`, `staging`). |
| `drift_score` | number | No | Current or latest drift score in [0.0, 1.0] when applicable. |
| `containment_tier` | string | No | For containment events: e.g. `throttle`, `restrict`, `isolate`, `kill`. |
| `approver_id` | string | No | For human_intervention: identifier of the approver (opaque or hashed). |

Additional custom fields MAY be added under `metadata` or as top-level extensions; implementers SHOULD namespace custom keys (e.g. `vendor_*`) to avoid clashes with future ACR schema versions.

## Validation Rules

1. **Schema version:** `acr_version` MUST be present and parseable. Consumers MAY reject unknown major versions.
2. **Event size:** Events SHOULD stay under 10 KB to avoid pipeline and storage bloat. Redact or truncate large payloads (e.g. `request.input`, tool call payloads) and document redaction policy.
3. **Timestamps:** `timestamp` MUST be ISO 8601 with timezone. Prefer UTC.
4. **Durable evidence before high-risk execution (§11):** If the logging/observability pipeline cannot durably record required ACR events, the system MUST prevent high-risk protected execution, record the failure through an alternate durable mechanism if available, and transition affected action classes to the documented safe-state if required evidence cannot be preserved. Asynchronous export is permitted only without bypassing this requirement.
5. **Integrity (§18):** High-risk events MUST be stored in tamper-evident or append-only form. Hash-chaining is one possible implementation.
6. **Completeness and linkage (§18):** MUST log all actions and all decisions. Required records MUST include the fields listed above, and correlation identifiers or equivalent linkage MUST connect the full action chain. Fields may be mapped to an equivalent implementation schema; omitting required evidence is not an equivalent mapping.
7. **Retention (§18):** MUST retain all ACR events at least 90 days and high-risk agent events at least 13 months.
8. **Privacy and export (§18):** MUST apply privacy-preserving treatment to sensitive fields, document field-category treatment (plaintext, redacted, hashed, tokenized, or omitted), and provide audit-ready export without manual reconstruction from unstructured logs.
9. **Ordering and attribution (§18):** Where records are sequenced or hash-chained, sequence MUST be assigned at decision issuance, and each decision record MUST be attributable to the action it governed through correlation linkage and its sequence position relative to that action. Persistence or export order MUST NOT redefine record order.
10. **Terminal account (§18):** When a run fails, times out, or is paused after dispatch, the evidence record MUST include a terminal account naming every dispatched effect with its `execution.outcome`. The account MUST be bound to the pre-dispatch records and authorizing decisions by correlation linkage. An outcome of `dispatched_unknown` MUST NOT be rewritten as `completed` or `cancelled_before_dispatch` without a reconciler's confirmed provider check.

## Versioning

- **Major** (e.g. 1.0 → 2.0): Breaking changes (removed or renamed required fields, changed types).
- **Minor** (e.g. 1.0 → 1.1): New optional fields or event types; backward compatible.
- **Patch:** Clarifications and non-structural edits only.

Implementations SHOULD include `acr_version` in every event so consumers can route or transform by version.

## Examples

### Illustrative `ai_inference` event

Examples demonstrate the field layout, not a complete evidence package or validated implementation output.

```json
{
  "acr_version": "1.0",
  "event_id": "550e8400-e29b-41d4-a716-446655440000",
  "event_type": "ai_inference",
  "timestamp": "2026-03-16T14:22:01Z",
  "correlation_id": "trace-abc-123",
  "decision": "allow",
  "agent": {
    "agent_id": "customer-support-01",
    "purpose": "customer_support"
  },
  "request": {
    "request_id": "req-abc-123"
  },
  "execution": {
    "duration_ms": 385
  },
  "policies": [
    { "policy_id": "pii_redaction", "decision": "allow" }
  ],
  "metadata": {
    "environment": "production",
    "drift_score": 0.12
  }
}
```

### `containment_action` event

```json
{
  "acr_version": "1.0",
  "event_id": "660e8400-e29b-41d4-a716-446655440001",
  "event_type": "containment_action",
  "timestamp": "2026-03-16T14:25:00Z",
  "correlation_id": "trace-xyz-789",
  "decision": "deny",
  "policies": [{"policy_id": "drift-containment", "decision": "deny"}],
  "agent": {
    "agent_id": "customer-support-01",
    "purpose": "customer_support"
  },
  "metadata": {
    "environment": "production",
    "drift_score": 0.72,
    "containment_tier": "restrict"
  }
}
```

## References

- [Pillar 4: Execution Observability](../pillars/04-execution-observability.md) — Architectural patterns and integration points
- [Implementation Guide: Telemetry & Observability](../guides/acr-implementation-guide.md#telemetry--observability-setup) — OpenTelemetry and dashboard guidance
- [OpenTelemetry Semantic Conventions](https://opentelemetry.io/docs/specs/semconv/) — For trace and attribute conventions

---

**ACR Framework v1.0** | [Home](../../README.md) | [Pillars](../pillars/README.md) | [Implementation Guide](../guides/acr-implementation-guide.md)
