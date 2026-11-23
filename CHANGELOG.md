# Changelog

All notable changes to the ACR Standard documentation and repository are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- Framework breadth and MCP gateway (v1.5.0 WS5, the pilot release): three surfaces, one evaluation path. (1) MCP gateway: a new deployable (`acr-mcp-gateway`, own FastAPI service on port 8080, `Dockerfile.mcp-gateway`, profile-gated Compose service, Kubernetes base manifests, validation overlay with a fixture MCP server) that fronts exactly one upstream MCP server and evaluates every `tools/call` through `POST /acr/evaluate` before forwarding, so proxied calls inherit §18 recording with sequence, policy, approvals, drift, containment, the kill switch, and WS1 observe semantics by construction; deny and escalate are never forwarded, enforce-mode modify forwards the transformed parameters, and evaluation failure fails closed. The first `tools/list` pins each tool's definition hash (SHA-256 over name/description/inputSchema): a later definition change blocks that tool's calls in the default `enforce` pinning mode (or stamps `tool_definition_changed` into the evaluation context in `log` mode), tools never listed are never forwarded (cross-server confusion gate), and restoring the original definition does not silently re-pin — re-pinning is an operator-reviewed restart. Responses pass the pillar-2 output filter and a size cap (default 1 MiB; oversized results are replaced, never delivered). Protocol scope is tools only: `resources/*` and `prompts/*` pass through logged, not evaluated. Direct-to-server bypass prevention is documented as a deployment/network-placement requirement the proxy cannot itself enforce (guide: `docs/mcp-gateway.md`). Red-team harness gains category 3 (poisoning, cross-server confusion, oversized responses; records a non-run and exits 2 without the gateway deployment), and a pytest parity suite replays the category-1 probes through the proxy against the real OPA binary, denying identically to the direct path with denied probes never reaching the fixture server. (2) OpenAI Agents SDK guard: `acr.sdk.openai_agents.guard_openai_tool` / `guard_openai_tools` at CrewAI-adapter parity — the guarded `FunctionTool` is built with `failure_error_function=None`, so deny/escalate raise `ACRDeniedError`/`ACREscalatedError` carrying the evaluate response (correlation and approval ids are the receipt binding); verified against openai-agents 0.25.0. (3) LangGraph guard verification pass against langchain-core 1.8.4 / langgraph 1.2.24 (`pip-audit` clean; the 2026-10-25 not-audit-clean note covered the legacy pre-1.0 family and is retired): fixed async dispatch drift in `build_langchain_tool` (coroutine tools and duck-typed async sessions previously took the sync path), and added the streaming/async/retry test matrix — LangGraph's default `RetryPolicy` does not retry `RuntimeError` subclasses, so a denial is final unless a graph explicitly opts into retrying it, and every retry is a fresh evaluation. The `integrations` extra now pins the verified langchain-core 1.x line. No schema migration; §18 semantics and existing decision outcomes unchanged.
- Bundle-hash stamping on decision records (v1.5.0 follow-up to WS3): every policy decision recorded in the §18 synchronous path, enforce and observe alike, now carries `bundle_hash` (migration 0021: `policy_decisions.bundle_hash`, nullable) — the SHA-256 of the runtime bundle that produced the evaluation, derived exactly as WS2 policy simulation and the activation gate derive it (sha256 over the archive bytes built by `build_active_runtime_bundle` from the currently active releases). Stamping is computed outside the recording transaction and is best-effort evidence: a bundle that cannot be rebuilt at recording time stamps NULL and can never become a recording failure, so §18 semantics, decision outcomes, and the fail-secure 503 path are unchanged. The hash surfaces in the decision explorer (`DecisionSummary.bundle_hash`; the decision chain now resolves its policy-bundle link from stamped decision rows when no approval authorization snapshot carries an identity), in evidence packages (decision JSONL records and the CSV index gain `bundle_hash`), and in the Sentinel decision export (`BundleHash`). Rows recorded before this change keep NULL.
- Integrations (v1.5.0 WS4, the pilot release): approvals and events inside the tools enterprises already run, delivered through a durable integration outbox (migration 0020: `integration_outbox`, `integration_delivery_attempts`; approval records gain `decided_channel`/`chat_actor_id`). Producing paths enqueue inside a savepoint — an integration failure can never break, block, or alter an approval, containment action, or decision — and a lifespan worker drains the outbox with retry, exponential backoff, and dead-lettering; every delivery attempt is recorded, so delivery itself is evidence. All integrations are off by default (all-off is byte-identical to pre-WS4); the pre-existing generic approval webhook is unchanged. Slack: Block Kit approval messages with Approve/Deny actions and containment/killswitch alerts; inbound interactivity callbacks verify the Slack v0 signature (5-minute tolerance) before anything can change, chat users resolve to operator identities only through the explicit `SLACK_APPROVER_MAP_JSON` mapping, and decisions execute through the pillar 6 approvals API handlers themselves, so binding, claim-once receipts, and execute-on-approve apply identically; the original message is re-rendered from the record's true state (decided/expired) via `chat.update`. Ships a Slack app manifest (`examples/slack/app-manifest.yaml`) and an operator smoke checklist; contract-tested against a mocked Slack Web API — live-workspace verification is the operator's smoke step, not a test-suite claim. Microsoft Teams (Adaptive Card approvals via incoming webhook with per-action signed tokens / outgoing-webhook HMAC, outcome cards), ServiceNow (incident creation via Table API with the ACR correlation id in the incident's `correlation_id` field; containment always, denials behind `SERVICENOW_INCIDENT_ON_DENY`), and Microsoft Sentinel (recorded-decision export via the Azure Monitor Logs Ingestion API, batched, enqueued strictly after the §18 recording commit) are built to the vendors' published formats and contract-tested against mocks only — each is labeled UNVERIFIED in code and docs, pending customer tenants. Guide: `docs/integrations.md`.
- Splunk HEC and syslog emitters (v1.5.0, completing the WS4 scope): migration 0022 extends the outbox `integration` check constraint, and the durable integration outbox gains two SIEM/log sinks that receive the full event stream — approval requested/decided, containment, kill switch, and recorded policy decisions enqueued strictly after the §18 recording commit with the same canonical decision-record shape as the Sentinel export. Splunk: batched newline-delimited JSON event envelopes (up to `SPLUNK_HEC_BATCH_MAX`, default 100) POSTed to the HTTP Event Collector endpoint with `Authorization: Splunk <token>` and the configured index/source/sourcetype; HEC's nonzero body codes are classified fatal (token disabled/inactive/invalid, dead-letter on first attempt) versus retryable, mirroring the Slack sender's fatal-error classification. Syslog: RFC 5424 messages over UDP or TCP (RFC 6587 octet-counted framing on TCP; plain transports only, no TLS in this release), severity mapped from the event (kill switch crit, containment err, denials warning, escalations notice), facility and app name configurable. Both are off by default (`SPLUNK_HEC_ENABLED` / `SYSLOG_ENABLED`), all-off writes no rows and makes no calls, secrets come only from the deployment environment and are never logged, and delivery failures retry/backoff/dead-letter through the shared outbox without ever touching the producing path. Both are built to the published formats and contract-tested against mocks only — labeled UNVERIFIED in code and docs, pending live instances. Guide: `docs/integrations.md`.
- Auditor surface (v1.5.0 WS3, the pilot release): time-boxed, read-only auditor grants (`POST /acr/operator-keys/auditor-grants`, security_admin only; roles forced to exactly `auditor`, expiry mandatory and capped by `AUDITOR_GRANT_MAX_LIFETIME_DAYS`, default 30; migration 0019 adds `operator_credentials.expires_at`; issuance and revocation are audit-logged, expired and revoked grants reject everywhere). Auditor scope is enforced centrally in the shared role dependency, not by convention: an auditor-only principal is rejected with 403 by every non-GET route — including the gateway evaluate path, via a dedicated guard — and by out-of-scope read surfaces (operator-key management, policy drafts, drift administration). Decision explorer: `GET /acr/decisions` (filters: agent, window, outcome, enforcement mode, reason substring, tool, correlation; paginated, newest first) and `GET /acr/decisions/chain/{identifier}` returning the full chain for one action — manifest snapshot as evaluated (from WS2 retention, explicitly reported absent when not captured, never silently replaced by the current manifest), policy ids and bundle identity where an approval snapshot carries one, decision records with §18 sequence, approval, execution receipt, and telemetry events, each link stated present or absent with a reason. Explorer reads are audit-logged. Evidence package generator (CLI `acr evidence-package` and `POST /acr/evidence-packages`): from live records for a window — summary counts/rates, agent inventory and manifests, policy release metadata, decision records (JSONL + CSV), approvals (parameters by hash, never value), containment events, drift, observe and simulation summaries, telemetry integrity verdicts, and the framework control mapping embedded from `docs/compliance/control-mapping.md` (wheel builds carry it as a packaged resource). Retained evaluation input payloads are never exported (hashes and state only). The package manifest hash-chains every file's SHA-256 and the bundled `verify_package.py` (Python standard library only, no ACR installation needed) re-checks hashes, chain integrity, file completeness, and summary/data consistency. Operator console gains a Decision Explorer tab. `docs/compliance/evidence-package.md` now distinguishes the generated runtime package from release/deployment evidence supplied externally. Guide: `docs/auditor-guide.md`.
- Policy simulation (v1.5.0 WS2, the pilot release): opt-in evaluation-input retention, off by default (`EVALUATION_INPUT_RETENTION_ENABLED`, 30-day default window), storing the effective evaluation input (manifest, action, enriched context) in the same transaction as the decision records (migration 0017: `evaluation_inputs`), with configured dot-path fields redacted to a fixed marker before storage and expired payloads purged by a background loop (decision records are never purged; the retention row remains as a tombstone). A replay engine (`acr.pillar2_policy.simulation`) re-evaluates retained inputs offline against a candidate Policy Studio bundle with the OPA binary — sharing the live path's decision derivation (`parse_opa_result` extracted from the policy engine) plus the gateway's output-filter decision step — and diffs simulated against recorded decisions (flips by direction and deciding rule, sample flipped cases from the stored redacted inputs). Coverage is reported honestly: decisions whose inputs were never retained or have been purged are counted as missing, never silently skipped. Every run is durably recorded (migration 0018: `policy_simulations`, plus `policy_releases.simulation_report_id`) with actor, bundle SHA-256, window, and a result hash. Surfaces: `POST /acr/policy-simulations` (security_admin), `GET /acr/policy-simulations/{run_id}` and `/summary.md` (auditor-readable), and CLI commands `acr simulate` / `acr purge-evaluation-inputs`. Promotion gate: while retention is on, activating a managed release requires a simulation report whose bundle hash matches the exact bundle activation would distribute; the gate is configurable (`POLICY_SIMULATION_GATE_ENABLED`, default on) and inert when retention is off. Guide: `docs/policy-simulation.md`.
- Observe mode (v1.5.0 WS1, the pilot release): per-agent enforcement mode (`enforce` default, `observe`), set at registration or through a dedicated operator-only transition endpoint (`POST /acr/agents/{id}/enforcement-mode`, audited with actor and reason; the generic update endpoint deliberately cannot change it). In observe mode the full policy evaluation runs unchanged and the decision is recorded synchronously with its §18 sequence and a mode stamp (migration 0016: `agents.enforcement_mode`, `policy_decisions.enforcement_mode`); recording failure still fails secure with 503. The call then proceeds: the evaluate response is HTTP 200 with `decision: "allow"`, `enforcement_mode: "observe"`, `would_be_decision`, and `enforced: false`; no approval request is created for a would-be escalation and no policy modification is substituted. Kill switch and graduated containment are exempt from observe and apply exactly as in enforce mode; mode comes only from the stored agent record, never from the request. New observe report (`GET /acr/agents/{id}/observe-report`) aggregates would-be decisions per agent over a window (counts by outcome, top blocked tools, sample decision references). Telemetry output objects carry `enforcement_mode`. Red-team harness gains category 2 (mode confusion). Guide: `docs/piloting-observe-mode.md`.

## [1.4.1] - 2026-11-22

### Fixed

- Default content guardrails: the destructive `rm` rule's protected-target set now covers the standard system roots (/bin, /boot, /dev, /etc, /lib, /lib64, /proc, /root, /sbin, /sys, /usr, /var) in addition to /, ~, and $HOME. The 2026-11-22 red-team run (category 1, executed on GitHub Actions against the v1.4.0 stack) showed `rm -rf /etc/passwd` passing the defaults in plain, quoted, and post-separator forms because only /, ~, and $HOME were protected; all forms now deny, including the base64-encoded and command-substitution variants. The set stays enumerated rather than "any absolute path": /tmp and other non-system absolute paths remain operator policy. Rego tests 56 -> 65; the packaged managed-core copy is synced byte-for-byte.

## [1.4.0] - 2026-11-22

### Added

- Installed `acr --version` CLI, offline LangGraph refund example, TypeScript decision-helper tests/example and Python parity inventory, customer-support Rego regression tests, and opt-in parameter PII policy example.
- Curated external resources and authenticated n8n webhook onboarding with a synthetic protected executor. See the n8n README for the exact validation scope.
- Safe approval resumption and durable execution receipts from PR #54 (already merged); these remain unreleased until a separate release is made.
- Reference-implementation conformance with the §18 ordering rule: every policy decision is assigned a per-agent sequence position when the decision is issued (new `decision_sequences` counter and `policy_decisions.sequence` column, migration 0015), and decisions are durably recorded in the same step, before the evaluate response is returned and before any approved action executes. If recording fails, the evaluation fails secure with a 503 `EVIDENCE_PERSISTENCE_FAILED` deny. Telemetry events carry the same `decision_sequence`, so the hash-chained observability copy can be checked against issuance order rather than flush order.
- CrewAI adapter (`acr.sdk.crewai`): `guard_crewai_tool` / `guard_crewai_tools` guard existing CrewAI `@tool` objects in one line per tool, returning a same-named CrewAI tool whose invocations ACR authorizes first. Verified against CrewAI 1.15.44.

### Changed

- Spec clarification (§18): the evidence-record requirements now state the ordering rule explicitly. Where records are sequenced or hash-chained, a decision record's sequence position is assigned when the decision is issued, not when the record is persisted, exported, or received, and each decision record is bound to the action it governed through correlation linkage and sequence position. Ordering by arrival, persistence, or completion time does not satisfy the requirement; asynchronous persistence and export remain permitted provided the assigned order reflects decision issuance. Clarification only: no new fields, no structural change, and the repository specification stays v1.2.0. Reference-implementation conformance is tracked separately.
- Fail-closed posture is now the default in every environment. Previously, Redis-backed runtime controls (rate limit, graduated containment, spend counters) silently degraded in `development`/`test`; degraded behavior now requires the explicit `ALLOW_DEGRADED_DEPENDENCIES` opt-in, and startup refuses that opt-in outside development/test. A deployment that forgets to set `ACR_ENV` no longer loses its controls silently.
- Drift detection cadence: the drift check now runs on every evaluation by default (new `DRIFT_CHECK_EVERY_N` setting, default 1; the previous hard-coded every-10th-evaluation throttle let slow, sparse deviations accumulate below the sampling line), and the baseline floor drops from 30 to 10 samples so a new agent does not run its first 30 actions with no drift signal.

### Fixed

- Brokered executor credentials are now bound to the execution payload: `X-ACR-Brokered-Credential` carries a `payload_sha256` claim (the binding `X-ACR-Execution-Token` already had), verification compares it against the actual request body, and pre-binding credentials without the claim are rejected on the payload-verification path. A credential minted for one payload can no longer be replayed with another.
- Token issuance rate limit no longer silently disables itself when Redis is unavailable; it fails closed with 503 unless degraded mode was explicitly opted into.
- Tool-name matching is canonicalized (case-insensitive, whitespace-trimmed) on both the action and the manifest allow/forbidden lists before policy evaluation, and the graduated-containment restrict check uses the same canonical form. `Send_Email` or ` send_email ` can no longer slip past an allowlist written for `send_email`.
- Graduated-containment tier comments corrected to the thresholds the code actually enforces (RESTRICT at drift >= 0.75, ISOLATE at >= 0.90; comments previously said 0.7 / 0.85).
- OpenTelemetry family moved from 1.45.1 / instrumentation 0.66b1 to 1.45.2 / 0.66b2: the 0.66b1 family version-locked `opentelemetry-api` to 1.45.1, which carries CVE-2026-126360. Dependency floors and instrumentation pins were updated together; the strict CI pip-audit gate passes on the new family.

### Documentation

- Distinguished normative PDF, repository specification, software release, and unreleased main. The current publisher PDF is v1.2.0 (2026-11-07); its §6 incorporation pin says repository v1.2.0, while the website says v1.3.1. That disputed pin remains unresolved and is not a conformance claim.
- Corrected reference-implementation listing and security support/version guidance. Historical entries below retain the publication state recorded at that time.

## [1.3.1] - 2026-11-08

### Fixed

- License packaging (PR #52): the gateway and kill-switch container images and the Python distributions now include the complete Apache 2.0 license text. Byte-for-byte license checks cover both built images, the wheel, and the source distribution before any publisher runs, and publishers reuse the exact validated artifacts without rebuilding.
- Supersedes v1.3.0 for new installations and upgrades. The v1.3.0 tag and artifacts are preserved so existing hashes, signatures, and pinned references remain reproducible. No runtime application-code changes in this patch.

## [1.3.0] - 2026-11-08

### Added

- Managed core policy upgrades (PR #51): a gateway release owns the exact core Rego bytes it requires (`common.rego`, `content_safety.rego`). The installed Python wheel and gateway image carry these resources, and OPA receives one aggregate bundle: packaged core + operator policies + active Policy Studio releases. Core identity is verified in the same OPA response; missing, stale, or mixed core fails closed on new policy evaluations. Includes per-gateway OPA sidecars, coordinated Compose upgrades and rollback, Policy Studio policy isolation, and migration checks that refuse modified legacy core, unsupported bundles, and lossy migration. Existing deployments require a one-time migration; see `implementations/acr-control-plane/docs/managed-policy-upgrades.md`.
- Reference-implementation work only: this release does not revise the repository specification (still v1.2.0) or the normative PDF.

### Fixed

- Kill-switch startup probe and healthy Kubernetes lifecycle checks.

## [1.2.1] - 2026-11-07

### Fixed

- Content guardrail quoting and command boundaries (PR #49): the default content-level guardrails now lex shell input quote-aware, scope every command/target pair to a single invocation, match protected paths after dequoting, detect path traversal in quoted arguments and `--option=../path` forms, inspect one explicit literal shell `-c` script without mistaking positional arguments for additional scripts, and read chmod's mode from its first non-option operand. OPA policy tests 48/48 (was 26).
- SQLAlchemy database tracing restored (PR #50): the instrumentor-supported SQLAlchemy 2.0 series and its declared compatibility extra are enforced, with emitted-span regressions for synchronous/asynchronous SQLite and PostgreSQL.

### Notes

- Implementation repair only: repository specification stays v1.2.0 and the normative PDF stays v1.0.1.

## [1.2.0] - 2026-11-07

### Added

- Spec v1.2: default content-level guardrails codified in Pillar 2 (Behavioral Policy Enforcement). Shipped default policies must inspect tool-parameter content, not only tool names: three deterministic rule classes (destructive shell commands, path traversal, base64-encoded destructive payloads), decided at the tool-call boundary and recorded in the evidence record. Prompt injection is explicitly out of scope for these defaults.
- Repository specification version 1.2.0, aligned with implementation release v1.2.0 (PR #47). The normative PDF remains v1.0.1 until a revised PDF is issued; see docs/README.md for the version scheme.
- Version badge updated to 1.2.0.

## [1.0] - 2026-03

### Added

- Initial release of the ACR Standard (Agentic Control at Runtime).
- Six pillar specifications: Identity & Purpose Binding, Behavioral Policy Enforcement, Autonomy Drift Detection, Execution Observability, Self-Healing & Containment, Human Authority.
- Control plane and runtime architecture documentation.
- Implementation guide with reference architectures (Kubernetes+OPA, AWS Serverless+Cedar, API Gateway+Custom).
- STRIKE threat model for AI-specific runtime threats.
- NIST AI RMF mapping and alignment narrative.
- Glossary, use cases, and FAQ.
- Telemetry schema specification (ACR event structure).
- CONTRIBUTING.md, ROADMAP.md, SECURITY.md, CODE_OF_CONDUCT.md.
- Documentation reorganized under `docs/` (pillars, architecture, specifications, compliance, security, guides).
- GitHub Actions workflow for markdown link checking.
- Issue templates for bug reports and feature requests.
- **Adoption and credibility (post-structure):**
- ADOPTION.md: maturity levels (1–3), "ACR-aligned" criteria, implementation listing process, badge and citation guidelines.
- GOVERNANCE.md: project goals, maintainer role, decision-making, contribution process, working groups (planned).
- STRIKE threat model expanded: attack scenarios, likelihood/impact, detection techniques, and detailed ACR control mapping per threat (S-T-R-I-K-E).
- NIST AI RMF subcategory-level mapping (Govern, Map, Measure, Manage) with ACR controls and references.
- Use cases: concrete scenarios for customer support, incident response, and financial analysis (sample policies, decision flows).
- Persona-based Get Started in docs (Architect, Security, Compliance, Implementer, Evaluator) with 3–5 step paths.
- Glossary expanded: Control Layer/Pillar, Policy Engine, Telemetry Schema, Kill Switch, Break-Glass, Purpose Binding, STRIKE mnemonic, ACR Maturity Level.
- README: "Why ACR?" positioning (OWASP/MITRE-style), adoption and governance links, citation and branding section, implementations section updated with ADOPTION reference.
- Pull request template for documentation and spec changes.

[1.3.1]: https://github.com/AdamDiStefanoAI/acr-standard/releases/tag/v1.3.1

[1.3.0]: https://github.com/AdamDiStefanoAI/acr-standard/releases/tag/v1.3.0

[1.2.1]: https://github.com/AdamDiStefanoAI/acr-standard/releases/tag/v1.2.1

[1.2.0]: https://github.com/AdamDiStefanoAI/acr-standard/releases/tag/v1.2.0

[1.0]: https://github.com/AdamDiStefanoAI/acr-standard/releases/tag/v1.0
