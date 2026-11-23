# ACR Control Plane v1.5.0 — release notes (DRAFT)

> **Draft for the v1.5.0 GitHub release.** Finalize at tag time:
> confirm the merged PR list, the final test count, and that red-team
> categories 1–3 have run green against the release candidate. The
> curated record is the CHANGELOG `[1.5.0]` section; these notes are
> the user-facing summary. The ACR Standard (specification) stays at
> v1.2.0 — this is an implementation release.

## The pilot release

v1.5.0 is the release an enterprise runs a pilot on. v1.4.x proved the
enforcement core: every decision evaluated against policy and recorded
synchronously, in order, before anything executes — fail-closed by
default. 1.5.0 answers the questions a pilot actually asks. Can we
roll this out without betting the fleet on it? **Observe mode.** Can
we know what a policy change would have done before we ship it?
**Policy simulation.** Can our auditors get evidence without getting
the keys to the kingdom? **Time-boxed auditor grants and evidence
packages.** Can approvals live where our operators already are?
**Slack, Teams, ServiceNow, Sentinel, Splunk, syslog.** Can it sit in
front of the frameworks and tool protocols we already run?
**LangGraph and OpenAI Agents guards, and an MCP gateway.** And the
question behind all of them — what does synchronous evidence cost?
**Measured, published, and reproducible** (`docs/benchmarks.md`):
on a ≈1.5-vCPU shared sandbox with everything co-located, the full
evaluate-and-record path runs at a p50 of ~27 ms (allow), ~32 ms
(deny), ~38 ms (escalate), and observe mode adds no measurable
overhead. Your topology will differ; the harness ships so you can
publish your own numbers instead of trusting ours.

## What's new

- **Observe mode (WS1).** Per-agent `enforce` | `observe`, changed
  only through a dedicated audited operator endpoint. Observe runs
  the full evaluation and records the decision synchronously with its
  would-be outcome, then lets the call proceed. Kill switch and
  containment are structurally exempt — they act in both modes. An
  observe report aggregates would-be decisions per agent.
- **Policy simulation (WS2).** Opt-in, off-by-default retention of
  evaluation inputs (redacted before storage, purged on a window),
  an offline replay engine that diffs a candidate bundle against
  recorded decisions with honest coverage counts, and a promotion
  gate: while retention is on, a managed release cannot activate
  without a simulation report for the exact bundle hash.
- **Auditor surface (WS3).** Time-boxed, read-only auditor grants
  enforced centrally at the route level (auditor-only principals are
  rejected by every non-GET route); a decision explorer that states
  every link in an action's chain as present or absent, never
  reconstructed; and a self-verifying evidence package (hash-chained
  manifest, standard-library-only verifier, payloads excluded by
  design).
- **Integrations (WS4 + completion).** A durable outbox carries
  approvals and events to Slack (Block Kit approvals that execute
  through the approvals API itself), Microsoft Teams, ServiceNow,
  Microsoft Sentinel, Splunk HEC, and syslog — all off by default,
  all unable to affect the producing path, every delivery attempt
  recorded. Decision records now also carry the **hash of the policy
  bundle** that produced them.
- **Framework breadth and MCP gateway (WS5).** The LangGraph guard
  re-verified against langchain-core 1.8.4 / langgraph 1.2.24 (with
  an async-dispatch drift fix); a new OpenAI Agents SDK guard
  (openai-agents 0.25.0); and `acr-mcp-gateway`, a deployable proxy
  that evaluates every MCP `tools/call` through the same §18 path
  before forwarding, pins tool definitions by hash, and filters
  responses. Resources and prompts pass through logged, not
  evaluated — that is the stated 1.5.0 scope.
- **Numbers pack (WS6).** The benchmark harness and published
  results, an HA reference topology with an explicit proven/unproven
  line, and the support matrix and policy
  (`docs/benchmarks.md`, `docs/high-availability.md`,
  `docs/support-policy.md`).

## Upgrade notes

- **Migrations 0016–0022** apply in order: 0016 enforcement mode,
  0017 evaluation inputs, 0018 policy simulations, 0019 auditor
  grant expiry, 0020 integration outbox, 0021 decision bundle hash,
  0022 outbox SIEM constraint. All are transactional; the standard
  initContainer/compose migration step handles them. No migration
  alters existing decision records; 0021 leaves pre-existing rows
  with a NULL bundle hash (see limitations).
- **No default changes.** Fail-closed stays the default posture.
  Every new capability is opt-in: integrations default off,
  evaluation-input retention defaults off, agents default to
  `enforce`. An upgrade with no configuration changes behaves like
  1.4.1 plus the new (dormant) surfaces.
- **New configuration** (all documented in `docs/configuration.md`
  and `docs/integrations.md`): `EVALUATION_INPUT_RETENTION_ENABLED`
  and its purge window, `POLICY_SIMULATION_GATE_ENABLED`,
  `AUDITOR_GRANT_MAX_LIFETIME_DAYS` (default 30), and the per-
  integration families `SLACK_*`, `TEAMS_*`, `SERVICENOW_*`,
  `SENTINEL_*`, `SPLUNK_HEC_*`, `SYSLOG_*`.
- **New deployables.** `acr-mcp-gateway` ships as its own image,
  a profile-gated compose service, and k8s base manifests. The
  default stack is unchanged if you do not enable the profile.

## Known limitations, stated plainly

- **Syslog has no TLS** in this release (plain UDP/TCP only).
- **Decision bundle hash is best-effort evidence.** It is computed
  outside the recording transaction so a bundle rebuild failure can
  never become a recording failure; such rows, and all rows recorded
  before migration 0021, carry NULL.
- **MCP resources and prompts are logged, not evaluated.** Only tool
  calls are enforced in 1.5.0. The gateway also cannot prevent a
  client from bypassing it to reach a server directly — that is a
  network-placement requirement on the deployment.
- **Teams, ServiceNow, Sentinel, Splunk, and syslog are
  UNVERIFIED**: built to the vendors' published formats and
  contract-tested against mocks only, pending live tenants and
  instances. Slack is contract-tested against a mocked Web API;
  live-workspace verification is a documented operator smoke step.
- **Published benchmark numbers are a single-host floor**, measured
  with the load generator co-located on a small shared VM. They are
  a reproduction target for equivalent hardware (±25% p50), not a
  production sizing claim.
- **Observe mode creates no approval requests** for would-be
  escalations and substitutes no policy modifications; it records
  and reports. Deciding what to do with an observe report is an
  operator workflow, not an automated promotion path.
