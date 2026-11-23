# Changelog

All notable changes to the ACR Standard documentation and repository are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

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
