# Changelog

All notable changes to the ACR Standard documentation and repository are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

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
