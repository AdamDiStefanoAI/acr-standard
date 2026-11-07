# Behavioral Policy Enforcement Specification

**ACR Control Layer 2 of 6**

## Purpose

Translate governance policies into machine-enforceable runtime rules that constrain AI system behavior during operation, ensuring compliance with security, privacy, and business requirements.

## Control Objectives

1. **Input Validation:** Verify all inputs meet security and compliance requirements before processing
2. **Output Filtering:** Prevent harmful, inappropriate, or policy-violating content in responses
3. **Action Authorization:** Control which operations AI systems can perform
4. **Data Handling Enforcement:** Ensure proper treatment of sensitive information
5. **Real-Time Policy Execution:** Enforce rules during inference, not post-hoc

## Scope

### In Scope
- Pre-inference input validation
- Post-inference output filtering
- Per-action authorization for tool/API calls
- Content-level inspection of tool parameters by default policies (spec v1.2)
- Data classification and handling enforcement
- Policy versioning and rollback
- Policy conflict resolution

### Out of Scope
- Prompt-injection detection by default policies (spec v1.2: explicitly out of scope; detecting injected instructions needs a dedicated detector)
- Model training governance (pre-deployment)
- Infrastructure access control (Layer 1: Identity Binding)
- Anomaly detection (Layer 3: Drift Detection)
- Incident response automation (Layer 5: Containment)

## Architectural Patterns

### Pattern 1: Policy-as-Code Engines

**Mechanism:** Declarative policy languages evaluated at runtime

**Technologies:**
- Open Policy Agent (OPA) with Rego language
- AWS Cedar policy language
- HashiCorp Sentinel
- Custom DSL implementations

**Implementation approach:**
```rego
# Example OPA policy for customer support agent

package acr.customer_support

# Deny prompts attempting SQL injection
deny["SQL injection attempt detected"] {
    input.prompt
    regex.match(`(?i)(union|select|insert|delete|drop)\s+`, input.prompt)
}

# Redact SSN from outputs
redact_ssn(output) = result {
    result := regex.replace(
        output,
        `\d{3}-\d{2}-\d{4}`,
        "***-**-****"
    )
}

# Allow only approved tools
allowed_tools = ["query_customer_db", "send_email", "create_ticket"]

deny["Unauthorized tool invocation"] {
    input.tool_call
    not input.tool_call.name in allowed_tools
}
```

**Design considerations:**
- Policy language complexity vs. expressiveness
- Evaluation performance (target <20ms per policy)
- Policy testing and validation before deployment
- Versioning strategy for policy updates

### Pattern 2: Rule-Based Validators

**Mechanism:** Pre-defined rules using regex, schema validation, or logic

**Technologies:**
- JSON Schema for input/output structure validation
- Regular expressions for pattern matching
- Business rule engines (Drools, Easy Rules)

**Implementation approach:**
```yaml
# Example rule-based policy configuration

input_rules:
  - rule_id: no_sql_injection
    type: regex_deny
    pattern: '(?i)(union|select|insert|delete|drop)\s+'
    error_message: "SQL injection attempt detected"
    
  - rule_id: max_prompt_length
    type: length_limit
    max_chars: 10000
    error_message: "Prompt exceeds maximum length"

output_rules:
  - rule_id: redact_ssn
    type: regex_replace
    pattern: '\d{3}-\d{2}-\d{4}'
    replacement: '***-**-****'
    
  - rule_id: redact_credit_card
    type: regex_replace
    pattern: '\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}'
    replacement: '****-****-****-****'

  - rule_id: block_financial_advice
    type: content_classification
    blocked_categories: ["financial_advice", "investment_recommendations"]
    confidence_threshold: 0.7
```

**Design considerations:**
- Rule ordering and evaluation sequence
- False positive handling
- Rule maintenance and updates
- Performance optimization (compiled regex, indexed lookups)

### Pattern 3: ML-Based Classifiers

**Mechanism:** Machine learning models evaluate content against policies

**Technologies:**
- Content safety APIs (Azure Content Safety, Perspective API)
- Custom classifiers (toxicity, PII, topic detection)
- Embedding-based similarity checks

**Implementation approach:**
```
Input Validation Flow:
1. Extract text from user input
2. Send to content safety classifier
3. Receive scores:
   - toxicity: 0.12 (safe)
   - sexual: 0.05 (safe)
   - violence: 0.89 (BLOCK)
4. Policy decision: DENY if any score > threshold

Output Filtering Flow:
1. Generate model response
2. Send to PII detection model
3. Identify entities:
   - "John Smith" (PERSON)
   - "123-45-6789" (SSN)
   - "john@example.com" (EMAIL)
4. Apply redaction:
   - Keep PERSON (contextually necessary)
   - Redact SSN → "***-**-****"
   - Redact EMAIL → "[EMAIL REDACTED]"
5. Return filtered response
```

**Design considerations:**
- Classifier latency (can be 100-500ms)
- Confidence threshold tuning (false positive vs. false negative trade-off)
- Model drift in classifiers themselves
- Fallback behavior when classifier unavailable

### Pattern 4: Hybrid Approach

**Mechanism:** Combine rule-based and ML-based techniques

**Implementation approach:**
```
Policy Evaluation Pipeline:

Phase 1: Fast Rules (target <5ms)
├── Regex-based SQL injection check
├── Prompt length limit
├── Known bad pattern matching
└── Decision: PASS → Phase 2, DENY → Block immediately

Phase 2: Structured Validation (target <10ms)
├── JSON schema validation
├── Data type checking
├── Required field verification
└── Decision: PASS → Phase 3, DENY → Block

Phase 3: ML Classification (target <100ms)
├── Content safety scoring
├── PII detection
├── Topic classification
└── Decision: PASS → Allow, DENY → Block

Total budget: <120ms for complete policy evaluation
```

**Design considerations:**
- Pipeline short-circuiting (fail fast)
- Parallel execution where possible
- Caching of ML classifier results
- Graceful degradation if ML services unavailable

## Policy Categories

### Input Validation Policies

**Security Policies:**
- Prompt injection detection
- Jailbreak attempt blocking
- SQL/command injection prevention
- Cross-site scripting (XSS) mitigation
- Malicious payload scanning

**Compliance Policies:**
- Input length limits (DoS prevention)
- Required field validation
- Data format verification
- Allowed character sets

**Business Policies:**
- Topic restrictions (e.g., no political content)
- Language requirements
- Context window limits

### Output Filtering Policies

**Privacy Policies:**
- PII redaction (SSN, credit cards, phone numbers)
- PHI filtering (healthcare data)
- Employee data protection
- Customer confidential information

**Content Safety Policies:**
- Hate speech blocking
- Violence/graphic content filtering
- Sexual content filtering
- Self-harm prevention
- Misinformation detection

**Business Policies:**
- Competitor mention restrictions
- Brand guideline compliance
- Tone/style requirements
- Forbidden topics or advice

### Action Authorization Policies

**Tool Invocation Policies:**
- Allowed tool allow-lists
- Parameter validation for tool calls
- Tool call frequency limits
- Tool dependency enforcement

**Data Access Policies:**
- Resource-level authorization
- Row/column-level access control
- Data export restrictions
- Modification vs. read-only constraints

**External API Policies:**
- Approved API endpoints
- Rate limiting per API
- Credential usage authorization
- Data transmission restrictions

### Data Handling Policies

**Classification Enforcement:**
- Automatic data classification tagging
- Classification-based access control
- Handling requirement enforcement (encrypt, anonymize, purge)

**Retention Policies:**
- Data lifetime limits
- Automatic purging schedules
- Archival requirements
- Audit trail retention

**Privacy Policies:**
- Consent verification before processing
- Purpose limitation enforcement
- Data minimization rules
- Right-to-deletion support

### Default content-level guardrails (spec v1.2)

**Background.** Before v1.2, the shipped default policies were tool-name-level only: they checked `tool_name` against allowlists and never inspected what an allowlisted tool was asked to do. An operator who allowlisted a shell tool therefore got no out-of-the-box protection against destructive commands, encoded payloads, or path traversal (GitHub issue #46; independent evaluation 2026-10-19). The v1.2 defaults close the deterministic part of that gap.

**Requirement.** Shipped default policies MUST inspect the content of tool parameters, not only the tool name. Inspection covers every string value in every tool parameter, at any depth (objects, arrays, nested objects), regardless of tool name. A content-level deny is decided at the tool-call boundary, before execution, and is recorded in the evidence record like any other policy decision (Pillar 4), with the rule class that fired.

**Rule classes.** The defaults cover deterministic patterns only, in three classes:

1. **Destructive shell commands.** `rm` with recursive and force flags on a protected target (filesystem root, home directory, or with `--no-preserve-root`); `mkfs` with a target; `dd` writing to a block device; the fork bomb; `chmod 777` on the filesystem root; shell redirection to a block device.
2. **Path traversal.** `..` used as a path segment (for example `../../etc/passwd`).
3. **Base64-encoded destructive payloads.** A whole string value that looks like base64 and decodes to printable text is re-checked against the destructive shell patterns.

**Narrowness.** Each destructive rule requires the dangerous command AND its dangerous target, so ordinary commands such as `rm -rf ./build` or `chmod 777 myfile.txt` do not match. Where a pattern or a boundary was ambiguous, the conservative option (fewer false positives) was chosen. The reference implementation for these rules is `policies/acr/content_safety.rego`, with 26 OPA tests (17 deny, 9 allow) in `content_safety_test.rego`.

**Explicit non-scope.** Prompt injection is OUT OF SCOPE for these defaults. No default rule claims to detect injected instructions. Detecting injected instructions needs a dedicated detector; operators who need prompt-injection protection must add one. The defaults are a floor, not complete protection: they cover the deterministic destructive patterns above and are not a substitute for per-tool parameter rules written by the operator.

## Enforcement Points

### Pre-Inference (Input Validation)
**Location:** Before model API call
**Latency target:** <50ms
**Actions:** Block, transform input, log warning

**Example flow:**
```
User prompt → Input policies → Transform/Block → Model API
```

### Post-Inference (Output Filtering)
**Location:** After model generates response
**Latency target:** <100ms
**Actions:** Redact, block entirely, modify content

**Example flow:**
```
Model response → Output policies → Redact/Block → Return to user
```

### Per-Action (Tool Authorization)
**Location:** Before each tool/API invocation
**Latency target:** <20ms per action
**Actions:** Allow, deny, require approval

**Example flow:**
```
Model requests tool call → Action policies → Allow/Deny → Execute tool
```

### Continuous (Data Handling)
**Location:** Throughout request lifecycle
**Latency target:** Minimal (passive classification)
**Actions:** Tag data, enforce handling, audit access

**Example flow:**
```
Data accessed → Classify → Apply handling rules → Audit
```

## Integration Points

### With Other ACR Layers

**Identity & Purpose Binding (Layer 1):**
- Policies reference agent_id and purpose
- Purpose determines which policies apply
- Example: `if agent.purpose == "customer_support" then allow_customer_db_query`

**Autonomy Drift Detection (Layer 3):**
- Policy violation frequency is a drift indicator
- Sudden changes in which policies trigger indicate behavioral shift
- Baseline includes "normal" policy violation rate (e.g., 0.5%)

**Execution Observability (Layer 4):**
- Every policy decision logged with:
  - policy_id, decision (allow/deny), latency, confidence (for ML)
- Telemetry enables policy effectiveness analysis
- Audit compliance through policy decision logs

**Self-Healing & Containment (Layer 5):**
- High-severity policy violations trigger containment
- Example: 3 SQL injection attempts in 5 minutes → isolate agent
- Policy violation severity determines response action

**Human Authority (Layer 6):**
- High-risk actions gate on human approval
- Humans can override policy decisions temporarily
- Policy modifications require human authorization

### With External Systems

**Content Safety APIs:**
- Azure Content Safety, Perspective API, OpenAI Moderation
- Real-time or batch evaluation
- Confidence scores inform policy decisions

**Data Loss Prevention (DLP):**
- Integration with enterprise DLP systems
- Unified policy management across AI and traditional apps
- Consistent PII/PHI detection

**Security Information and Event Management (SIEM):**
- Policy violation events to SIEM
- Correlation with other security events
- Alert triggering for high-severity violations

## Design Considerations

### Latency Budget

**Total policy overhead target: <150ms**

Breakdown:
- Input validation: <50ms
- Output filtering: <100ms
- Action authorization: <20ms per action

**Mitigation strategies for latency:**
- Cache policy evaluation results
- Parallel policy execution where independent
- Short-circuit evaluation (fail fast)
- Async policy checks for non-blocking policies

### False Positive Management

**Challenge:** Overly strict policies block legitimate use

**Strategies:**
1. **Confidence thresholds:** Require high confidence for blocking (e.g., >0.9)
2. **Human review queue:** Flag uncertain cases for manual review
3. **Feedback loops:** Users report false positives, policies adjusted
4. **Shadow mode:** Run new policies in observe-only mode first
5. **Gradual rollout:** Deploy to small percentage of traffic initially

### Policy Conflict Resolution

**Scenario:** Multiple policies apply to same input, with conflicting decisions

**Resolution strategies:**
1. **Deny-by-default:** If any policy denies, overall decision is deny
2. **Priority-based:** Policies have explicit priority ordering
3. **Most-restrictive:** Apply strictest policy when conflicts exist
4. **Context-dependent:** Resolution logic varies by scenario

**Recommendation:** Deny-by-default for security/compliance, priority-based for business policies

### Policy Versioning

**Challenge:** Policies evolve but need version control

**Approaches:**
1. **Semantic versioning:** Major/minor/patch versions for policies
2. **Immutable policies:** Each change creates new policy, old archived
3. **Git-based:** Store policies in version control
4. **Rollback capability:** Quickly revert to previous policy version

**Recommendation:** Git-based with semantic versioning, immutable for audit trail

## Failure Modes

### Policy Engine Unavailable
**Symptom:** Cannot evaluate policies
**Impact:** All requests blocked (fail-closed) or allowed (fail-open)
**Mitigation:**
- Fail-closed by default (deny all if policy engine down)
- Local policy cache for degraded mode
- Redundant policy engines with load balancing
**Recovery:** Restore policy engine, review decisions made during outage

### Policy Evaluation Timeout
**Symptom:** Policy check exceeds latency budget
**Impact:** Degraded user experience or blocked requests
**Mitigation:**
- Hard timeout (e.g., 500ms) triggers fail-safe action
- Cache previous decisions for identical inputs
- Async evaluation for non-critical policies
**Recovery:** Investigate slow policies, optimize or remove

### False Positive Storm
**Symptom:** Legitimate requests suddenly blocked at high rate
**Impact:** Service disruption, user complaints
**Mitigation:**
- Canary deployments for policy changes
- Automated rollback on error rate spike
- Human override capability for manual bypass
**Recovery:** Revert policy, analyze root cause, adjust thresholds

### PII Leak Despite Filtering
**Symptom:** Sensitive data appears in output despite redaction policies
**Impact:** Compliance violation, data breach
**Mitigation:**
- Multiple layers of PII detection (regex + ML)
- Post-release scanning of logs for leaked PII
- Alert on redaction failure
**Recovery:** Incident response, notify affected parties, strengthen policies

## Evaluation Criteria

An ACR-compliant Behavioral Policy Enforcement implementation should satisfy:

### Mandatory Requirements
1. **Pre-Inference Input Validation:** All inputs checked before model invocation
2. **Post-Inference Output Filtering:** All outputs checked before returning to user
3. **Action Authorization:** Tool/API calls require policy approval
4. **Deny by Default:** Unpermitted actions blocked without explicit allow
5. **Policy Logging:** Every policy decision recorded in audit trail
6. **Versioned Policies:** Policies tracked with version control
7. **Content-level defaults (spec v1.2):** Shipped default policies inspect tool-parameter content, not only tool names, and deny the three deterministic rule classes (destructive shell commands, path traversal, base64-encoded destructive payloads) at the tool-call boundary

### Recommended Features
1. **Multiple Policy Types:** Supports rule-based, schema, and ML-based policies
2. **Latency SLA:** 95th percentile policy overhead <200ms
3. **False Positive Feedback:** Mechanism for users to report incorrect blocks
4. **Shadow Mode:** Ability to test policies without enforcement
5. **Policy Testing:** Automated tests validate policy behavior before deployment

### Advanced Capabilities
1. **Context-Aware Policies:** Decisions vary based on user, time, location
2. **Adaptive Policies:** Policies learn and adjust thresholds over time
3. **Explainable Decisions:** Policy violations include human-readable explanation
4. **Policy Composition:** Complex policies built from simpler primitives

## Open Research Questions

1. **Policy Language Standardization:** Is there an optimal DSL for AI governance policies?

2. **Dynamic Policy Adjustment:** How should policies automatically tune based on observed false positive/negative rates?

3. **Cross-Model Policy Portability:** Can policies written for GPT-4 work for Claude without modification?

4. **Policy Learning from Human Feedback:** Can policies be generated or refined through RLHF-style processes?

5. **Privacy-Preserving Policy Evaluation:** How to evaluate policies without exposing sensitive data to policy engine?

6. **Adversarial Policy Robustness:** How resilient are policies to deliberate evasion attempts?

## References

**Policy Languages:**
- Open Policy Agent (OPA) Documentation
- AWS Cedar Policy Language
- XACML (eXtensible Access Control Markup Language)

**Content Safety:**
- Azure Content Safety API
- Perspective API (Google Jigsaw)
- OpenAI Moderation API

**Data Protection:**
- GDPR Guidelines on Automated Decision-Making
- NIST Privacy Framework
- ISO/IEC 29100 Privacy Framework

**Related Frameworks:**
- OWASP AI Security and Privacy Guide
- MITRE ATLAS (Adversarial Threat Landscape for AI Systems)

---

**Previous:** [Identity & Purpose Binding](./01-identity-purpose-binding.md) | **Next:** [Autonomy Drift Detection](./03-autonomy-drift-detection.md)

**ACR Standard v1.2** | [Home](../../README.md) | [All Pillars](./README.md)
