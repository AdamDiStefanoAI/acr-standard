# Execution Observability Specification

**ACR Control Layer 4 of 6**

> Conformance requirements below summarize the normative v1.0.1 PDF. Architectural patterns, sample timings, thresholds, and technologies are illustrative unless the normative standard requires them. See [source precedence and versions](../README.md#normative-source-and-document-versions).

## Purpose

Provide the decision trails, tool traces, policy events, and state history needed for assurance, investigation, and operational trust. You cannot govern what you cannot reconstruct. Execution observability ensures every autonomous action is visible, reviewable, and audit-ready.

## Control Objectives

1. **Structured Trace Logging:** Correlation IDs link model calls, tool invocations, policy decisions, and downstream effects into reconstructible action chains
2. **Tamper-Evident Audit Logs:** Append-only logging with cryptographic chain-of-custody for high-risk events prevents post-hoc manipulation of evidence
3. **Retention & Compliance:** Log retention periods satisfy regulatory and organizational requirements (13-month minimum for high-risk, 90-day minimum for all)
4. **Audit-Ready Exports:** Structured exports support investigations, assurance reviews, and regulator requests without manual log parsing
5. **Real-Time Dashboards:** Operational visibility into agent behavior, policy effectiveness, and drift trends for continuous monitoring

## Scope

### In Scope
- Structured telemetry event generation and collection
- Correlation ID propagation across distributed action chains
- Append-only logging with integrity verification
- Log retention policy enforcement
- Audit export generation
- Dashboard and alerting integration
- Privacy-preserving log handling (PII redaction, hashing)

### Out of Scope
- Infrastructure monitoring (handled by platform engineering)
- Network traffic logging (handled by network security)
- Model training telemetry (pre-deployment concern)
- End-user session tracking (application responsibility)

## Architectural Patterns

### Pattern 1: Structured Event Telemetry

**Mechanism:** Every ACR control plane decision generates a structured JSON event conforming to the ACR Telemetry Schema

**Technologies:**
- OpenTelemetry SDK for instrumentation
- JSON Lines (.jsonl) for streaming ingest
- Protobuf for high-throughput binary encoding

**Implementation approach:**
```
Event Generation Pipeline:

1. Agent requests action
2. Control plane generates event_id (UUID v4) and correlation_id
3. Each pillar evaluation appends to the event:
   - Identity check result → agent object
   - Policy evaluation → policies array
   - Drift score → metadata object
   - Tool execution details → execution object
4. Complete event emitted to telemetry pipeline
5. Correlation ID propagated to downstream system calls

Event schema: see ACR Telemetry Schema Specification (../specifications/telemetry-schema.md)

Event types:
  - ai_inference: Standard model invocation
  - policy_decision: Policy check without inference
  - drift_alert: Anomaly detection event
  - containment_action: Automated response triggered
  - human_intervention: Manual override or approval
```

**Design considerations:**
- Schema validation before emission (reject malformed events)
- Event size budget: target <10KB per event (redact large payloads)
- Async emission: telemetry must not block the action pipeline
- Schema versioning: backward-compatible evolution with semantic versioning

### Pattern 2: Correlation ID Propagation

**Mechanism:** A single correlation ID traces an action from initial request through every downstream system interaction

**Technologies:**
- OpenTelemetry trace context (W3C Trace Context standard)
- Custom X-Correlation-ID headers
- Distributed tracing (Jaeger, Zipkin, X-Ray)

**Implementation approach:**
```
Trace Structure for a Single Agent Action:

Trace ID: abc-123-def-456
├── Span: ACR Control Plane Evaluation (parent)
│   ├── Attribute: agent_id = "customer-support-01"
│   ├── Attribute: action = "send_email"
│   │
│   ├── Span: Identity Validation
│   │   ├── Attribute: identity_valid = true
│   │   └── Duration: 8ms
│   │
│   ├── Span: Policy Evaluation
│   │   ├── Attribute: policy_id = "pii_redaction"
│   │   ├── Attribute: decision = "allow"
│   │   ├── Attribute: transformations = 1
│   │   └── Duration: 22ms
│   │
│   ├── Span: Tool Execution (send_email)
│   │   ├── Attribute: tool = "send_email"
│   │   ├── Attribute: destination = "customer@example.com"
│   │   └── Duration: 340ms
│   │
│   └── Span: Drift Score Update
│       ├── Attribute: drift_score = 0.12
│       └── Duration: 3ms
│
└── Total Duration: 385ms
```

**Design considerations:**
- Correlation ID must be generated at the control plane entry point, not by the agent
- Propagate via HTTP headers (W3C traceparent) for cross-service calls
- Include correlation_id in all log events for join-ability
- Support multi-hop traces: agent → control plane → tool → external API → response

### Pattern 3: Append-Only Audit Logging

**Mechanism:** Tamper-evident, write-once log storage with cryptographic integrity verification

**Technologies:**
- AWS CloudTrail / S3 Object Lock (WORM storage)
- Azure Immutable Blob Storage
- HashiCorp Vault Audit Backend
- Custom: hash-chained log entries (each entry includes hash of previous)

**Implementation approach:**
```
Hash-Chained Audit Log:

Entry N:
{
  "sequence": 1042,
  "event": { ... ACR telemetry event ... },
  "timestamp": "2026-03-16T14:22:01Z",
  "previous_hash": "sha256:a1b2c3d4...",
  "entry_hash": "sha256:e5f6g7h8..."
}

Verification:
  hash(Entry N) == Entry N+1.previous_hash
  → If chain breaks, tampering detected

Storage tiers:
  Hot (0-30 days):   Indexed, queryable, real-time dashboards
  Warm (30-90 days): Queryable with slight latency, compressed
  Cold (90d-13mo):   Archive storage, retrieval on request
  Glacier (13mo+):   Compliance archive, bulk retrieval only
```

**Design considerations:**
- Hash chain verification should run as a background job (hourly for hot, daily for warm)
- WORM storage prevents even administrators from modifying logs
- Log encryption at rest is mandatory for high-risk agent logs
- Separate log pipeline from agent runtime (agent crash must not lose logs)

### Pattern 4: Privacy-Preserving Observability

**Mechanism:** Log everything needed for governance while protecting sensitive data

**Technologies:**
- Field-level redaction (PII patterns → "[REDACTED]")
- Cryptographic hashing (user_id → SHA-256 hash)
- Differential privacy for aggregate metrics
- Tokenization for reversible pseudonymization

**Implementation approach:**
```
Privacy Treatment by Field:

| Field              | Treatment         | Reversible? |
|--------------------|-------------------|-------------|
| user_id            | SHA-256 hash      | No          |
| prompt text        | Redact PII        | No          |
| completion text    | Redact PII        | No          |
| IP address         | Truncate to /24   | No          |
| tool parameters    | Redact PII values | No          |
| agent_id           | Plain text        | N/A         |
| policy decisions   | Plain text        | N/A         |
| correlation_id     | Plain text        | N/A         |

Compliance modes:
  GDPR:    Hash user IDs, redact PII, support right-to-deletion
  HIPAA:   Redact PHI, encrypt at rest and transit, access controls
  PCI-DSS: Never log full card numbers, redact CVV/expiry
```

**Design considerations:**
- PII detection must run before log emission, not after
- Redaction is irreversible — cannot recover redacted data from logs
- Hash-based pseudonymization allows correlation without exposing identity
- Right-to-deletion: must be able to purge all events for a given user_id hash

## Integration Points

### With Other ACR Layers

**Identity & Purpose Binding (Pillar 1):**
- Every telemetry event includes agent_id and purpose from identity binding
- Identity lifecycle events (creation, rotation, revocation) are logged as observability events
- Identity validation latency is tracked as an operational metric

**Behavioral Policy Enforcement (Pillar 2):**
- Every policy decision (allow/deny/transform) is logged with policy_id and justification
- Policy evaluation latency is tracked per policy and per agent
- Policy effectiveness is measurable through observability data (deny rates, false positive reports)

**Autonomy Drift Detection (Pillar 3):**
- Drift detection consumes telemetry data as its primary input
- Drift scores are written back into telemetry events as metadata
- Drift alert events are logged through the same observability pipeline

**Self-Healing & Containment (Pillar 5):**
- Kill switch activations, isolation events, and rollbacks are logged as containment_action events
- Containment response time is measurable from telemetry timestamps
- Evidence preservation relies on observability log integrity

**Human Authority (Pillar 6):**
- Approval requests, decisions, and timeouts are logged as human_intervention events
- Break-glass activations include mandatory audit log entries
- Approval response time SLA is measurable from telemetry data

### With External Systems

**SIEM Platforms:**
- Export ACR events to Splunk, Sentinel, QRadar via structured JSON or CEF format
- Severity mapping: policy denials → WARN, drift alerts → ERROR, containment → CRITICAL
- Correlation with network and application security events in unified timeline

**Observability Platforms:**
- OpenTelemetry Collector for vendor-neutral telemetry pipeline
- Datadog APM for real-time trace visualization and alerting
- Grafana + Loki for log aggregation and dashboard creation
- AWS CloudWatch + X-Ray for native AWS observability

**Compliance & Audit:**
- SOC 2 evidence generation from audit log exports
- ISO 27001 audit trail requirements satisfied by structured logging
- Regulator data requests fulfilled via audit-ready export format

## Enforcement Points

### Telemetry Emission (Inline)
- Event generated at control plane decision point
- Emitted asynchronously to avoid blocking action pipeline
- **Latency impact:** <2ms (async write to buffer)

### Log Pipeline (Near-Real-Time)
- Events flow through collection, enrichment, and routing
- PII redaction applied before storage
- **Latency impact:** 5–30 seconds from emission to queryability

### Audit Verification (Background)
- Hash chain integrity verification runs on schedule
- Retention policy enforcement (auto-archive, auto-delete)
- **Latency impact:** None (background process)

## Design Considerations

### Log Volume Management

**Challenge:** High-throughput agents can generate millions of events per day

**Mitigation strategies:**
1. **Sampling:** Log 100% of policy denials and containment events; sample 10% of routine allows for high-volume agents
2. **Aggregation:** Roll up per-minute metrics for baseline comparison instead of per-event analysis
3. **Tiered storage:** Hot → warm → cold → glacier progression with automatic lifecycle management
4. **Event size limits:** Cap individual events at 10KB; truncate or hash large payloads

### Log Pipeline Reliability

**Challenge:** Log pipeline failure means lost evidence

**Mitigation strategies:**
1. **Local buffer:** Agent-side buffer retains events during pipeline outage (min 1 hour)
2. **Dead letter queue:** Failed log writes go to retry queue, not /dev/null
3. **Dual write:** Critical events (denials, containment) written to both primary and backup pipeline
4. **Health monitoring:** Alert when log pipeline latency exceeds 60 seconds or drop rate exceeds 0.1%

### Observability of Observability

**Challenge:** How do you know the observability system itself is working?

**Mitigation strategies:**
1. **Canary events:** Synthetic test events injected every 5 minutes, verified at pipeline exit
2. **Completeness checks:** Compare event count at emission vs. storage — alert on discrepancy
3. **Hash chain verification:** Automated integrity checks detect tampering or data loss
4. **Pipeline latency monitoring:** Track time from event emission to queryability

## Failure Modes

### Log Pipeline Unavailable
**Symptom:** Events not reaching storage; dashboards go stale
**Impact:** Governance blind spot — agent actions not auditable during outage
**Mitigation:**
- Local event buffer on agent side (minimum 1 hour retention)
- Dead letter queue for failed writes with automated retry
- Alert operations team within 5 minutes of pipeline failure
**Recovery:** Flush local buffers to pipeline after recovery; verify completeness

### Log Tampering Detected
**Symptom:** Hash chain verification fails; sequence gap in audit log
**Impact:** Evidence integrity compromised; compliance violation
**Mitigation:**
- WORM storage prevents modification even by administrators
- Multi-region replication provides independent verification copies
- Immediate alert to security team on integrity failure
**Recovery:** Isolate affected log segment; restore from replication; investigate access logs

### Storage Capacity Exhaustion
**Symptom:** Log writes rejected; retention policies not executing
**Impact:** New events lost; compliance retention requirements at risk
**Mitigation:**
- Capacity monitoring with 30-day forecast
- Automated lifecycle management (hot → warm → cold transitions)
- Emergency sampling: reduce to critical-events-only mode during capacity crunch
**Recovery:** Expand storage; backfill from local buffers if available; review retention policy sizing

### PII Leak in Logs
**Symptom:** Sensitive data found in stored logs despite redaction policies
**Impact:** Privacy violation, regulatory exposure
**Mitigation:**
- Multiple layers of PII detection (regex + ML classifier)
- Post-storage scanning for leaked PII patterns
- Redaction applied before pipeline emission, not after storage
**Recovery:** Purge affected log entries; notify privacy team; strengthen redaction rules

## Evaluation Criteria

### Mandatory Requirements (§18)
1. **Complete action and decision logging:** MUST log all actions and decisions, including ALLOW, DENY, MODIFY, and ESCALATE, with the applicable policy results and execution/approval metadata.
2. **Required fields and linkage:** MUST include schema version, event ID, timestamp, event type, agent ID, purpose, request or correlation ID, decision outcome, relevant policy results, execution metadata for execution events, and approval metadata for approval/escalation events. A correlation identifier or equivalent linkage MUST connect the full action chain.
3. **Retention:** MUST retain all ACR events for at least 90 days and high-risk agent events for at least 13 months.
4. **High-risk integrity:** High-risk events MUST use tamper-evident or append-only storage; a cryptographic hash chain is one possible implementation.
5. **Audit export:** MUST support audit-ready reconstruction without manual reconstruction from unstructured logs.
6. **Privacy:** MUST apply privacy-preserving treatment to sensitive log fields and document, by field category, whether fields are plaintext, redacted, hashed, tokenized, or omitted.
7. **Durable-recording failure (§11):** Inability to durably record required events MUST block high-risk protected actions, record failure through an alternate durable mechanism if available, and transition affected action classes to the documented safe-state if required evidence cannot be preserved.
8. **Decision ordering and attribution (§18):** Where ACR records are sequenced or hash-chained, a decision record's sequence position MUST be assigned when the decision is issued, not when the record is persisted, exported, or received. Each decision record MUST be bound to the action it governed, through correlation linkage and through its position relative to that action, so a verifier can determine which decision authorized, modified, escalated, or denied each action. Ordering by arrival, persistence, or completion time does not satisfy this requirement. Asynchronous persistence and export remain permitted, provided the assigned order reflects decision issuance.
9. **Terminal account of dispatched effects (§18):** When a run fails, times out, or is paused after one or more protected effects were dispatched, the evidence record MUST include a terminal account naming every dispatched effect and stating its outcome as completed, cancelled before dispatch, or dispatched unknown. An effect whose outcome cannot be confirmed MUST be recorded as dispatched unknown, never inferred as completed or cancelled. The terminal account MUST be bound to the pre-dispatch records and the authorizing decisions by correlation linkage, so a verifier can determine, for each effect, what was authorized, what was dispatched, and what its outcome was.

### Recommended Features
1. **Cryptographic hash chaining** as one way to implement high-risk tamper evidence
2. **OpenTelemetry integration** for vendor-neutral telemetry pipelines
3. **Real-time dashboards** for agent operations, policy effectiveness, and drift trends
4. **Configurable privacy treatment** suited to deployment requirements
5. **Sampling of supplemental diagnostics** only; sampling MUST NOT omit required action/decision records

### Advanced Capabilities
1. **Tamper-evident verification** with automated hash chain integrity checks
2. **Cross-agent trace correlation** linking actions across multi-agent workflows
3. **Automated compliance evidence** generation for SOC 2, ISO 27001, and ISO 42001
4. **Predictive capacity planning** based on log volume growth trends

## Open Research Questions

1. **Minimal Sufficient Telemetry:** What is the minimum set of fields that must be logged to support full decision reconstruction without excessive storage cost?

2. **Privacy vs. Auditability Trade-off:** How do we balance the need for complete audit trails with data minimization principles required by GDPR and similar regulations?

3. **Cross-Organization Observability:** When agents interact across organizational boundaries (vendor APIs, partner systems), how should telemetry be shared without exposing proprietary data?

4. **Semantic Log Search:** Can natural language queries ("show me all times the support agent accessed billing data last week") replace structured query languages for incident investigation?

5. **Real-Time Compliance Verification:** Can log data be continuously validated against compliance requirements (SOC 2, ISO 27001) in real-time rather than periodic audits?

6. **Observability Cost Optimization:** As agent deployments scale to thousands, how do we maintain comprehensive observability without observability infrastructure becoming the dominant cost?

## References

**Standards:**
- W3C Trace Context Specification
- OpenTelemetry Semantic Conventions
- ISO 8601 (Date and time format)
- RFC 4122 (UUID)

**Technologies:**
- OpenTelemetry Collector Documentation
- AWS CloudTrail Immutable Logging
- Azure Immutable Blob Storage
- Jaeger Distributed Tracing

**Related Specifications:**
- [ACR Telemetry Schema Specification](../specifications/telemetry-schema.md)

---

**Previous:** [Autonomy Drift Detection](./03-autonomy-drift-detection.md) | **Next:** [Self-Healing & Containment](./05-self-healing-containment.md)

**ACR Framework v1.0** | [Home](../../README.md) | [All Pillars](./README.md)
