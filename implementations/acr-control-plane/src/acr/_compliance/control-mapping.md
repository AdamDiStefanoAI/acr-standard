# Control Mapping

This is a reference mapping for enterprise review. It is not a certification claim, legal opinion, or guarantee that every deployment is compliant out of the box.

## Mapping Approach

The goal of this document is to show where the control plane materially supports common governance and security frameworks, and where operator implementation work is still required.

## NIST AI RMF Reference Mapping

| NIST AI RMF Theme | ACR Capability | Operator Evidence Needed |
|---|---|---|
| Govern | policy releases, operator roles, approval workflows, containment authority | role design, policy approval process, release approvals |
| Map | agent manifests, purpose binding, allowed tools, risk tiering | agent inventory, business-purpose approval, data classification |
| Measure | telemetry, evidence export, drift scoring, validation results | alert thresholds, review cadence, issue tracking |
| Manage | allow/deny/escalate or modify decisions, kill switch, release rollback | incident response procedures, runtime exception handling, promotion controls |

## SOC 2 Common Criteria Reference Mapping

| SOC 2 Area | ACR Capability | Shared Responsibility Note |
|---|---|---|
| CC6 Logical Access | operator RBAC, signed sessions, API keys, agent token validation | identity-provider configuration and access reviews are external |
| CC7 System Operations | health and readiness endpoints, telemetry, evidence bundles, drift signals | monitoring, alerting, and on-call response remain deployment responsibilities |
| CC8 Change Management | versioned policy drafts, releases, activation history, rollback | change approvals and segregation of duties must be implemented by the operator |
| CC9 Risk Mitigation | fail-secure behavior, containment, approval gating, downstream authorization | enterprise risk acceptance and exception management remain external |

## ISO/IEC 42001 Theme-Level Mapping

| ISO 42001 Theme | ACR Capability | Shared Responsibility Note |
|---|---|---|
| Governance and leadership | operator roles, approval authority, policy lifecycle | organizational policy, leadership review, and accountability are external |
| Planning and risk treatment | agent boundaries, runtime guardrails, escalation paths | risk registers and treatment acceptance remain operator-managed |
| Operational controls | hot-path policy enforcement, output filtering, containment, brokered credentials | deployment hardening and downstream system control must be implemented externally |
| Monitoring and evaluation | telemetry, evidence export, drift scoring, failure/load/DR validation | periodic review, audit collection, and corrective action tracking remain external |
| Improvement | governed baseline lifecycle, policy versioning, rollback | continuous improvement process is organizational, not product-only |

## EU AI Act Support Mapping

| EU AI Act Obligation Theme | ACR Capability | Shared Responsibility Note |
|---|---|---|
| Risk management | policy enforcement, containment, approval gating, failure validation | deployers still need a formal risk-management process |
| Logging and traceability | telemetry, evidence bundles, approval records, signed integrity chain | retention, access control, and legal hold remain external |
| Human oversight | escalation queues, approval endpoints, operator console, kill switch | operators must define when human review is mandatory |
| Accuracy, robustness, cybersecurity | runtime enforcement, dependency checks, brokered credentials, signed releases | infrastructure hardening, testing depth, and production controls remain shared |

## What This Package Does Not Claim

It does not claim:

- SOC 2 certification
- ISO 42001 certification
- automatic EU AI Act compliance
- completeness of organizational governance outside the control plane

It does claim:

- the implementation provides technical controls that map cleanly into those programs
- the repo now includes artifacts that make those controls easier to assess and verify
