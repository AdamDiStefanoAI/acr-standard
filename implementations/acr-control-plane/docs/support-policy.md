# Support matrix and policy

*v1.5.0 WS6 (the numbers pack). This is a support **policy**, not an
SLA: it states what is supported, what was verified and how, and the
targets the project works to. It makes no uptime or response-time
guarantees.*

## Platform matrix (v1.5.0)

| Component | Supported | Verified in this release |
|---|---|---|
| Python | 3.11, 3.12 (`requires-python >=3.11`) | CI test matrix on 3.11 and 3.12 |
| OPA | 0.70.x (the bundle tooling refuses other majors) | 0.70.0 in compose, k8s, and all validation paths |
| PostgreSQL | 14+ (any asyncpg-compatible server) | 16.2 (benchmark run); compose/CI images |
| Redis | 6.x / 7.x, single endpoint (`REDIS_URL`) | 6.2.14 (benchmark run). No Sentinel/Cluster client wiring in this release — see `docs/high-availability.md` |
| Deployment | Docker Compose (reference stack), Kubernetes base + production overlay | Full-stack and managed-upgrade validation workflows |
| ACR Standard (specification) | v1.2.0 — v1.5.0 is an implementation release; the spec does not move | §18 conformance as in v1.4.0 |

## Framework SDK guards

| Guard | Verified against | Notes |
|---|---|---|
| CrewAI (`acr.sdk.crewai`) | CrewAI 1.15.44 | Verified in v1.4.0; unchanged in 1.5.0 |
| LangGraph (`acr.sdk.langgraph`) | langchain-core 1.8.4, langgraph 1.2.24 | WS5 verification pass; streaming/async/retry matrix in tests. A denial is final under LangGraph's default `RetryPolicy` unless a graph opts into retrying it; every retry is a fresh evaluation |
| OpenAI Agents SDK (`acr.sdk.openai_agents`) | openai-agents 0.25.0 | New in WS5; deny/escalate raise with the evaluate response as the receipt binding |

## MCP gateway scope

Protocol scope for 1.5.0 is **tools only**: `tools/list` and
`tools/call` are evaluated before forwarding. `resources/*` and
`prompts/*` pass through and are logged, **not evaluated**. Preventing
direct-to-server bypass is a deployment/network-placement requirement
on the operator; the gateway documents this rather than claiming to
enforce it (`docs/mcp-gateway.md`).

## Integration verification status

Mirror of `docs/integrations.md`; the labels mean exactly what they
say and nothing more.

| Integration | Status |
|---|---|
| Slack approvals & alerts | Contract-tested against a mocked Slack Web API, including signature verification and chat-decision binding. Live-workspace verification is a documented operator smoke step (app manifest + checklist ship in `examples/slack/`) |
| Generic approval webhook (pre-existing) | Unchanged by 1.5.0; covered by the n8n validation workflow |
| Microsoft Teams | **UNVERIFIED** — built to published formats, contract tests against mocks only |
| ServiceNow | **UNVERIFIED** — Table API contract tests against mocks only |
| Microsoft Sentinel | **UNVERIFIED** — Logs Ingestion API shape contract-tested against mocks only |
| Splunk (HEC) | **UNVERIFIED** — built to the published HEC format, contract tests against mocks only |
| Syslog | **UNVERIFIED** — RFC 5424 shape contract-tested against mocked sockets only. **Plain UDP/TCP only: no TLS in this release** |

## Version support window

- The **current minor release** (1.5.x) receives bug and security
  fixes.
- The **previous minor release** (1.4.x) receives security fixes for
  six months after the current minor ships.
- Older releases are unsupported; the upgrade path is forward through
  each minor's Alembic migrations, which are transactional and
  race-safe (`docs/high-availability.md`).

## Security response targets

Targets, not guarantees:

- Critical CVE in a shipped dependency or a remotely exploitable
  flaw in the control plane: assessment within 2 business days,
  fixed release or published mitigation within 7 days.
- High severity: assessment within 5 business days, fix in the next
  patch release.
- The strict CI pip-audit gate runs on every change; dependency
  families move together when a CVE forces it (the v1.4.0
  OpenTelemetry move is the worked example).

## Deprecation policy

- Public surfaces (HTTP API, SDK guards, configuration keys, CLI)
  deprecate in one minor release and are removed no earlier than the
  next minor, with the deprecation and its replacement recorded in
  the CHANGELOG when announced.
- Configuration defaults that affect the security posture (fail-closed
  behavior, drift cadence) change only in minor releases, never in
  patches, and are called out as upgrade notes — v1.4.0's fail-closed
  default change is the template.

## Security regression testing per release

The red-team harness (`scripts/red_team_harness.py`) maps to release
gating as follows:

| Category | Covers | Status |
|---|---|---|
| 1 | Content-guardrail evasion (direct path) | Implemented; must run green against the release candidate |
| 2 | Observe-mode confusion (WS1) | Implemented; must run green |
| 3 | MCP gateway: poisoning, cross-server confusion, oversized responses (WS5), plus the category-1 parity suite through the proxy | Implemented; must run green |
| 4–10 | — | **Not implemented.** A category that did not run is never reported as a pass |

A release is not done until every implemented category has run green
against the release candidate. Categories are added when the
corresponding surface ships, not before.
