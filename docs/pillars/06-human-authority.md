# Human Authority Specification

**ACR Control Layer 6 of 6**

> Conformance requirements below summarize the normative v1.0.1 PDF. Architectural patterns, sample timings, thresholds, and technologies are illustrative unless the normative standard requires them. See [source precedence and versions](../README.md#normative-source-and-document-versions).

## Purpose

Ensure that accountable authority over consequential decisions remains human. Autonomous systems may assist, accelerate, and recommend, but humans retain override rights, escalation authority, and decision control over high-impact outcomes. This pillar defines who can approve, who can override, when escalation is required, and how exception paths are governed.

## Control Objectives

1. **Action Tiering:** Classify all agent actions into risk-based tiers (low-risk autonomous, medium-risk gated, high-risk human-approval required) with clear criteria for each level
2. **Escalation Authority Matrix:** Define who can approve what, with delegation limits, approval hierarchy, and fallback paths
3. **Timeout & Fallback Handling:** Ensure high-risk actions do not proceed indefinitely without human response — define SLAs, timeout behavior, and safe defaults
4. **Break-Glass Override:** Provide emergency bypass capability with mandatory logging, multi-party authorization, time-limited tokens, and required after-action review
5. **Accountability Chain:** Maintain an unbroken record of human decisions, approvals, and overrides for audit and governance purposes

## Scope

### In Scope
- Action risk tiering criteria and classification
- Approval workflow design and implementation
- Escalation path definition and routing
- Timeout handling and fallback behavior
- Break-glass emergency override procedures
- Human decision logging and accountability
- Approval queue management and SLA enforcement

### Out of Scope
- End-user consent flows (application layer responsibility)
- HR approval workflows unrelated to AI operations
- Model selection and evaluation decisions (pre-deployment governance)
- Budget approval for AI infrastructure (organizational finance)

## Architectural Patterns

### Pattern 1: Risk-Based Action Tiering

**Mechanism:** Every agent action is classified into a risk tier that determines whether it proceeds autonomously, queues for review, or blocks until explicitly approved

**Technologies:**
- Policy-as-code rules that evaluate action risk at runtime
- Risk scoring functions based on action type, dollar value, data sensitivity, and agent risk tier
- Configuration-driven tier definitions (YAML/JSON)

**Implementation approach:**
```
Action Tier Definitions:

Tier 1 — Low Risk (Autonomous):
  Criteria: Read-only data access, knowledge base search, internal logging
  Behavior: Auto-approved, logged
  Examples:
    - Query customer record (read-only)
    - Search knowledge base
    - Generate report from existing data
  Approval: None required
  SLA: N/A

Tier 2 — Medium Risk (Gated):
  Criteria: State-modifying actions, outbound communications, cost-incurring operations
  Behavior: Async review, proceeds if approved within SLA
  Examples:
    - Send email to customer
    - Create support ticket
    - Update customer record
    - Tool invocation with cost < $50
  Approval: Agent owner or designated reviewer
  SLA: 1 hour

Tier 3 — High Risk (Human Required):
  Criteria: Financial transactions, PII bulk access, production deployments, irreversible actions
  Behavior: Blocked until human explicitly approves
  Examples:
    - Issue refund > $100
    - Access PII bulk export
    - Deploy to production
    - Delete customer data
    - Modify billing records
  Approval: Senior reviewer or manager (per escalation matrix)
  SLA: 4 hours (default)
  Timeout: Deny (action does not proceed)
```

**Design considerations:**
- Tier assignment must be deterministic and auditable (not subjective)
- Tier boundaries should be configurable per agent without code changes
- Edge cases: actions that span tiers (e.g., small refund that becomes large) need re-evaluation
- New action types default to Tier 3 (high risk) until explicitly classified

### Pattern 2: Approval Queue System

**Mechanism:** Dedicated queue service receives approval requests, routes them to appropriate reviewers, enforces SLAs, and handles timeouts

**Technologies:**
- Custom microservice with persistent queue (Redis, SQS, database-backed)
- Slack bot for reviewer interaction
- Step Functions / Temporal for workflow orchestration
- Mobile push notifications for time-sensitive approvals

**Implementation approach:**
```
Approval Request Flow:

1. Agent action classified as Tier 2 or Tier 3
2. Control plane creates approval request:
   {
     request_id: "uuid",
     agent_id: "customer-support-01",
     action: { tool: "issue_refund", parameters: { amount: 250 } },
     risk_tier: 3,
     required_approver_role: "finance_reviewer",
     sla_deadline: "2026-03-16T18:22:00Z",
     timeout_action: "deny",
     context: { customer_id: "...", reason: "...", session_trace: "..." }
   }
3. Queue routes to eligible approvers based on escalation matrix
4. Notification sent: Slack message, email, mobile push
5. Reviewer sees: action summary, agent context, risk assessment
6. Reviewer decides: Approve / Deny / Escalate / Request More Context
7. Decision logged and returned to control plane
8. If approved: action proceeds with approval metadata attached
9. If denied: agent notified, alternative action suggested if available
10. If timeout: default action (deny for Tier 3, configurable for Tier 2)

Escalation on Non-Response:
  T+0:    Primary reviewer notified
  T+50%:  Reminder sent to primary reviewer
  T+75%:  Secondary reviewer notified (backup)
  T+100%: Timeout action executed (default: deny)
```

**Design considerations:**
- Approval requests must include sufficient context for informed decisions (not just "approve this action?")
- Reviewers should see agent identity, purpose, recent action history, and drift score
- Queue depth monitoring: alert if pending approvals exceed capacity
- Batch approval: allow reviewers to approve multiple similar low-risk items at once (Tier 2 only)
- Approval delegation: allow temporary delegation during reviewer PTO

### Pattern 3: Break-Glass Override

**Mechanism:** Emergency bypass that allows actions to proceed outside normal approval flows, with mandatory logging, multi-party authorization, and required after-action review

**Technologies:**
- Time-limited override tokens (JWT with short expiry)
- Multi-party authorization (2+ approvers required)
- Mandatory audit log entries with tamper-evident storage
- After-action review workflow integration

**Implementation approach:**
```
Break-Glass Activation:

1. Operator determines emergency override is needed
   (e.g., automated containment is blocking critical business operation)

2. Operator requests break-glass token:
   POST /acr/break-glass
   {
     agent_id: "customer-support-01",
     reason: "Customer escalation requires immediate refund during system maintenance",
     operator: "oncall@example.com",
     requested_duration_minutes: 60,
     requested_permissions: ["issue_refund"]
   }

3. Second approver confirms (multi-party requirement):
   POST /acr/break-glass/confirm
   {
     request_id: "uuid",
     confirmer: "security-lead@example.com"
   }

4. Time-limited override token issued:
   {
     token: "eyJ...",
     expires_at: "2026-03-16T15:22:00Z",
     permissions: ["issue_refund"],
     max_uses: 5,
     audit_id: "bg-2026-0316-001"
   }

5. Agent operates with override token (all actions logged with audit_id)

6. Token expires automatically after duration

7. After-action review required within 24 hours:
   - What happened?
   - Why was normal approval insufficient?
   - What actions were taken under override?
   - Should policy or thresholds be adjusted?
```

**Design considerations:**
- Break-glass tokens must have maximum duration (4 hours recommended, 24 hours absolute max)
- Multi-party authorization prevents single-person bypass of controls
- All actions under break-glass are logged with elevated audit priority
- After-action review is mandatory, not optional — tracked as compliance requirement
- Break-glass usage frequency is a metric: high frequency indicates policy/threshold problems

### Pattern 4: Escalation Authority Matrix

**Mechanism:** Formal definition of who can approve what, with delegation limits, backup paths, and conflict resolution

**Technologies:**
- RBAC/ABAC with approval-specific roles
- Configuration-driven matrix (YAML/database)
- Integration with enterprise directory (LDAP, Azure AD, Okta)

**Implementation approach:**
```
Escalation Authority Matrix:

| Action Category    | Tier | Primary Approver      | Backup Approver    | Delegation Allowed |
|--------------------|------|-----------------------|--------------------|--------------------|
| Customer comms     | 2    | Support team lead     | Support manager    | Yes (to senior agents) |
| Refund < $100      | 2    | Support team lead     | Finance reviewer   | Yes |
| Refund $100-$1000  | 3    | Finance reviewer      | Finance manager    | No |
| Refund > $1000     | 3    | Finance manager       | VP Finance         | No |
| PII access         | 3    | Privacy officer       | CISO               | No |
| Production deploy  | 3    | Engineering manager   | VP Engineering     | No |
| Data deletion      | 3    | Data governance lead  | CISO               | No |
| Break-glass        | —    | Any 2 of: CISO, VP Eng, CTO | —           | No |

Delegation Rules:
  - Delegation expires after 7 days or delegator return (whichever first)
  - Delegate cannot further delegate
  - Delegation is logged with delegator, delegate, scope, and duration
  - Tier 3 actions cannot be delegated (explicit in matrix)

Conflict Resolution:
  - If primary and backup disagree: escalate to next level
  - If no approver available within SLA: timeout action (deny for Tier 3)
  - If approver has conflict of interest: auto-route to backup
```

**Design considerations:**
- Matrix must be version-controlled with change history
- Matrix changes require approval from governance authority (not self-approved)
- Regular review (quarterly) to ensure matrix reflects current organizational structure
- Integration with HR systems to auto-update when personnel change roles

## Integration Points

### With Other ACR Layers

**Identity & Purpose Binding (Pillar 1):**
- Human approvers are authenticated through enterprise identity system
- Agent identity context is included in approval requests for reviewer visibility
- Approval decisions are bound to approver identity with non-repudiation

**Behavioral Policy Enforcement (Pillar 2):**
- Policies determine which actions require human approval (Tier 2/3 classification)
- Policy changes (new rules, threshold adjustments) require human authorization
- Break-glass overrides temporarily modify policy enforcement with full logging

**Autonomy Drift Detection (Pillar 3):**
- Drift alerts at warning level notify human reviewers for assessment
- Critical drift may require human authorization before agent can resume
- Human investigation findings inform drift threshold adjustments

**Execution Observability (Pillar 4):**
- All approval requests, decisions, and timeouts are logged as human_intervention events
- Approval response time is measurable from telemetry data for SLA tracking
- Break-glass usage is tracked as a governance metric

**Self-Healing & Containment (Pillar 5):**
- Recovery from containment requires human approval through the authority framework
- Kill switch activation by operators is logged with full identity and justification
- Break-glass may override automated containment in emergencies

### With External Systems

**Communication Platforms:**
- Slack / Microsoft Teams for approval notifications and interactive approval buttons
- Email for asynchronous approval with secure approval links
- Mobile push notifications for time-sensitive Tier 3 approvals
- SMS as last-resort escalation for critical approvals

**Ticketing Systems:**
- Jira / ServiceNow for approval request tracking and audit trail
- Automatic ticket creation for break-glass events
- SLA monitoring integration for approval queue health

**Enterprise Directory:**
- LDAP / Azure AD / Okta for approver role resolution
- Automatic matrix updates when personnel change roles
- Group-based routing for approval queue assignment

## Enforcement Points

### Approval Gate (Synchronous)
- Agent action blocked at control plane until approval received or timeout
- Approval check adds latency equal to human response time (minutes to hours)
- For Tier 3: no bypass without break-glass token
- **Latency impact:** Human-dependent (minutes to hours)

### Timeout Handler (Background)
- SLA timer starts when approval request is created
- Escalation logic executes at configured intervals (50%, 75%, 100% of SLA)
- Timeout action executed when SLA expires (configurable: deny, escalate, safe-default)
- **Latency impact:** None (timer-based)

### Break-Glass Endpoint (Synchronous)
- Token issuance requires multi-party authentication
- Token validation on every action during override period
- Token auto-expiry enforced by control plane
- **Latency impact:** Token validation <5ms

## Design Considerations

### Approval Fatigue

**Challenge:** Too many approval requests cause reviewers to rubber-stamp without evaluation

**Mitigation strategies:**
1. **Right-size Tier 2:** Only gate actions that genuinely warrant human review — over-classification erodes reviewer attention
2. **Batch approvals:** Allow reviewers to approve multiple similar Tier 2 items at once (e.g., "approve all customer emails from this agent today")
3. **Smart routing:** Route to reviewers with domain expertise, not a generic queue
4. **Context-rich requests:** Include agent summary, risk assessment, and recent history so reviewers can decide quickly
5. **Approval metrics:** Monitor approval time and rubber-stamp rate (>95% approval rate may indicate over-classification)

### Accountability Gap

**Challenge:** When an agent takes an action that was auto-approved (Tier 1), who is accountable for the outcome?

**Mitigation strategies:**
1. Agent owner is accountable for all Tier 1 actions — this is defined at registration time
2. Tier classification itself is a governance decision with an approver
3. Audit trail connects every action to the policy that permitted it and the person who approved the policy
4. Periodic review of Tier 1 outcomes to identify actions that should be reclassified

### SLA Tuning

**Challenge:** Too-short SLAs cause legitimate approvals to timeout; too-long SLAs delay critical operations

**Mitigation strategies:**
1. Start with conservative SLAs (4 hours for Tier 3, 1 hour for Tier 2) and adjust based on data
2. Track approval response time percentiles (P50, P95) and timeout rates
3. Different SLAs for business hours vs. after-hours
4. Emergency path (break-glass) available when SLA is insufficient for urgent situations

## Failure Modes

### Approval Queue Backlog
**Symptom:** Pending approval requests grow faster than reviewers can process
**Impact:** Agent operations stall; SLA timeouts increase; business processes delayed
**Mitigation:**
- Queue depth monitoring with alert at configurable threshold (e.g., >20 pending)
- Automatic escalation to backup reviewers when queue exceeds capacity
- Temporary Tier 2 → Tier 1 downgrade for low-risk actions during backlog (with logging)
- Staff capacity planning based on historical approval volume
**Recovery:** Clear backlog with batch approvals; review tier classifications for over-classification

### Approver Unavailable
**Symptom:** Primary and backup approvers both unreachable within SLA
**Impact:** Tier 3 actions timeout and are denied; business impact
**Mitigation:**
- Minimum 2 approvers per action category in escalation matrix
- On-call rotation for Tier 3 approval authority
- Graceful timeout behavior: deny + notify agent owner + create follow-up ticket
- Break-glass path available for genuine emergencies
**Recovery:** Ensure coverage gaps are addressed in escalation matrix review

### Break-Glass Abuse
**Symptom:** Break-glass used routinely instead of through normal approval flow
**Impact:** Controls effectively bypassed; governance integrity compromised
**Mitigation:**
- Track break-glass frequency as a governance metric (target: <2 per month)
- Mandatory after-action review for every break-glass event
- High frequency triggers governance review of approval SLAs and tier classifications
- Multi-party requirement makes casual break-glass usage impractical
**Recovery:** Review root causes of break-glass events; adjust policies, thresholds, or SLAs to reduce need

### Approval Spoofing
**Symptom:** Unauthorized party approves an action by impersonating a legitimate approver
**Impact:** Unauthorized agent actions with fabricated approval chain
**Mitigation:**
- Approver authentication through enterprise SSO (not email-based approval links alone)
- Multi-factor authentication required for Tier 3 approvals
- Approval decisions signed with approver's identity token
- Approval audit trail with IP address, device, and session metadata
**Recovery:** Revoke spoofed approvals; contain affected agent; investigate identity compromise

## Evaluation Criteria

### Mandatory Requirements (§20)
1. **Action tiering:** MUST distinguish autonomous actions, actions requiring review/gating, and actions requiring explicit human approval before execution. New or unclassified high-impact actions MUST default to the highest approval class until classified.
2. **Escalation authority matrix:** MUST define approval roles by action category, delegation limits, backup approvers, and timeout behavior.
3. **Durable approval and context:** Escalated actions MUST have a durable approval record and present agent identity, declared purpose, requested action and parameters, policy basis, current drift state, and timeout deadline to the reviewer.
4. **Execution gate:** MUST prevent autonomous execution before approval, enforce timeout behavior, and log approval, denial, override, and timeout outcomes.
5. **Independent human authority:** Controls MUST remain operable if the agent runtime or model infrastructure is unavailable.
6. **Reconciliation ownership and terminal bound on waiting:** A run that enters a waiting-for-reconciliation state MUST have a named reconciliation owner and a stated reconciliation deadline. The waiting state MUST convert to a stated terminal state at the deadline whether or not the owner responds; an unanswered owner MUST NOT leave a run waiting with budget or reservations held indefinitely. Reservations for effects recorded as dispatched unknown MUST remain held until the reconciler releases them. The owner MUST be notified with the operation ID and the last confirmed state.

### Optional Break-Glass Capability (§20)
Break-glass MAY be provided. If provided, it MUST be scoped and time-limited, logged in tamper-evident form with approver identity, subject to mandatory post-use review, and approved in advance by a defined authority. The multi-party procedure and sample durations in Pattern 3 are implementation choices, not universal conformance requirements.

### Recommended Features
1. **Automated escalation** on reviewer non-response
2. **Communication platform integration** for reviewer notification
3. **Batch approval capability** for appropriate requests within defined authority and scope
4. **Delegation support** with time-limited scope and audit trail

### Advanced Capabilities
1. **Adaptive tier classification** that adjusts risk tier based on agent drift score and recent behavior
2. **Approval pattern analysis** detecting rubber-stamping, approval fatigue, or unusual approval patterns
3. **Predictive queue management** forecasting approval volume and staffing needs
4. **Cross-agent approval correlation** identifying patterns where multiple agents request similar high-risk actions

## Open Research Questions

1. **Optimal Human Oversight Level:** How much human oversight is enough? Over-approval creates fatigue and rubber-stamping; under-approval creates risk. Is there a measurable optimum?

2. **Human-AI Approval Collaboration:** Can AI assist human reviewers by pre-scoring approval requests, highlighting anomalies, or suggesting decisions — without undermining human authority?

3. **Scalability of Human Authority:** As organizations deploy hundreds or thousands of agents, how does the approval model scale? Is there a tipping point where human-in-the-loop becomes operationally infeasible?

4. **Accountability in Multi-Agent Chains:** When Agent A's action is approved by a human but triggers Agent B's autonomous action that causes harm, how is accountability distributed?

5. **Break-Glass Governance:** What governance framework prevents break-glass from becoming a normalized bypass? How do organizations measure whether their break-glass usage indicates healthy exceptions vs. systemic control failures?

6. **Cross-Organizational Authority:** When agents operate across organizational boundaries (vendor agents accessing customer systems), whose human authority governs? How are approval chains federated?

## References

**Standards:**
- ISO/IEC 42001 8.2 (Human Oversight of AI Systems)
- NIST AI RMF GOVERN 2.1 (Roles and Responsibilities)
- NIST CSF GV.RR (Roles, Responsibilities, and Authorities)
- ISO 27001 A.5.3 (Segregation of Duties)
- ISO 27001 A.5.4 (Management Responsibilities)
- EU AI Act Article 14 (Human Oversight)

**Workflow Technologies:**
- AWS Step Functions for approval orchestration
- Temporal.io for long-running workflow management
- Slack Block Kit for interactive approval messages
- PagerDuty Event Orchestration

**Related Frameworks:**
- NIST SP 800-53 AC-6 (Least Privilege)
- COBIT 2019 (Governance of Enterprise IT)
- ITIL 4 (Service Management)

---

**Previous:** [Self-Healing & Containment](./05-self-healing-containment.md)

**ACR Framework v1.0** | [Home](../../README.md) | [All Pillars](./README.md)
