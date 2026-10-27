<div align="center">

<img src="https://runtimecontrol.io/assets/ACR_1.png" alt="ACR Standard" width="780" />

# **ACR Standard**
### ACR: Agentic Control at Runtime

**The control plane your autonomous AI agents need before you let them touch production.**

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg?style=for-the-badge)](LICENSE)
[![Version](https://img.shields.io/badge/version-1.0.1-00d4ff.svg?style=for-the-badge)](https://github.com/AdamDiStefanoAI/acr-standard/releases)
[![Status](https://img.shields.io/badge/status-reference%20implementation-blue.svg?style=for-the-badge)](implementations/acr-control-plane/README.md)
[![Python](https://img.shields.io/badge/python-3.11%2B-3776AB.svg?style=for-the-badge&logo=python&logoColor=white)]()

[![NIST AI RMF](https://img.shields.io/badge/maps_to-NIST_AI_RMF-darkblue.svg)](docs/compliance/acr-nist-ai-rmf-mapping.md)
[![ISO 42001](https://img.shields.io/badge/maps_to-ISO_42001-darkblue.svg)](docs/compliance)
[![SOC 2](https://img.shields.io/badge/maps_to-SOC_2-darkblue.svg)](docs/compliance)
[![OPA](https://img.shields.io/badge/policy-OPA%20%2F%20Rego-7D4698.svg?logo=openpolicyagent&logoColor=white)]()
[![FastAPI](https://img.shields.io/badge/API-FastAPI-009688.svg?logo=fastapi&logoColor=white)]()
[![Postgres](https://img.shields.io/badge/store-PostgreSQL-336791.svg?logo=postgresql&logoColor=white)]()
[![Redis](https://img.shields.io/badge/cache-Redis-DC382D.svg?logo=redis&logoColor=white)]()
[![Kubernetes](https://img.shields.io/badge/deploy-Kubernetes-326CE5.svg?logo=kubernetes&logoColor=white)]()
[![LinkedIn](https://img.shields.io/badge/LinkedIn-ACR_Standard-0A66C2?logo=linkedin&logoColor=white)](https://www.linkedin.com/company/acr-standard/)

**[📖 Docs](./docs)** · **[🚀 Quickstart](#-quickstart-60-seconds)** · **[🏛️ For Executives](#-for-security--risk-executives)** · **[⚙️ For Engineers](#%EF%B8%8F-for-engineers)** · **[🛡️ Threat Model](docs/security/acr-strike-threat-model.md)** · **[📋 Adopt ACR](./ADOPTION.md)**

---

</div>

## 🎯 Pick Your Path

| You are a... | Start here |
|---|---|
| 🏛️ **CISO, CRO, GRC lead, board member** — *I need to understand the risk and the answer* | **[For Security & Risk Executives ↓](#-for-security--risk-executives)** |
| ⚙️ **Engineer, SRE, security architect** — *I need to read the code and run the thing* | **[For Engineers ↓](#%EF%B8%8F-for-engineers)** |

---

# 🏛️ For Security & Risk Executives

## The problem in one sentence

> **You are about to give software the authority to act on behalf of your business, and your existing AI governance program stops at the moment that software goes into production.**

Traditional AI governance — model cards, pre-deployment reviews, NIST AI RMF documentation, ISO 42001 paperwork — happens **before** an AI system runs. It produces binders, not brakes. The moment an autonomous agent starts accessing customer data, calling APIs, issuing refunds, or filing tickets on your behalf, your design-time controls have nothing to enforce against.

That gap is where the risk lives: a perfectly compliant agent on day one can drift, be manipulated, or simply behave unexpectedly on day ninety — and there is nothing in your stack to notice, throttle, or stop it.

## What ACR is, in plain terms

**ACR is the seatbelt, airbag, ABS and crumple zone for autonomous AI.** It is a runtime control plane that sits between your AI agents and the systems they touch, and it enforces your governance policies on every single action the agent attempts — before that action ever leaves the building.

It does not replace your AI governance program. It is the part of the program that **executes**.

## What ACR gives you

| Outcome | What it means in practice |
|---|---|
| 🛑 **A real "off switch."** | A single command, kept on a separate system from the agent itself, instantly disables an agent globally. Even a compromised control plane cannot silently re-enable it. |
| 🚦 **Graduated containment, not just on/off.** | If an agent starts behaving abnormally, the system automatically throttles it, then restricts its tools, then escalates everything to a human, and only kills it as a last resort. Four tiers, no operator paged at 3am for the small stuff. |
| 👁️ **A complete, signed audit trail of every decision.** | Every action an agent attempted, every policy that fired, every approval, every override — all hashed and exportable as a tamper-evident evidence bundle for auditors and incident response. |
| 🧑‍⚖️ **Human-in-the-loop, where it matters.** | High-risk actions (refunds above a threshold, schema changes, cross-tenant access) automatically pause and route to a named human approver with an SLA. If the human doesn't respond in time, the action auto-denies. |
| 📉 **Drift detection on agent *behavior*, not just model accuracy.** | The system continuously baselines what "normal" looks like for each agent and raises a score when an agent starts using new tools, denying more often, or behaving more erratically than its baseline allows. |
| 📜 **Compliance you can actually evidence.** | Pre-built mappings to NIST AI RMF, ISO/IEC 42001, and SOC 2, with the audit artifacts to back them up. Auditors get a download, not a meeting. |

## The six pillars (the executive version)

ACR enforces six categories of control on every agent action:

| # | Pillar | What it answers |
|---|---|---|
| 1️⃣ | **Identity & Purpose Binding** | *"Is this really our agent, and is it doing what we hired it to do?"* |
| 2️⃣ | **Behavioral Policy Enforcement** | *"Is this specific action allowed by our policy, right now?"* |
| 3️⃣ | **Autonomy Drift Detection** | *"Is this agent behaving the way it did last week?"* |
| 4️⃣ | **Execution Observability** | *"Can we prove what happened, to whom, when, and why?"* |
| 5️⃣ | **Self-Healing Containment** | *"If it starts misbehaving, does it stop itself before we have to?"* |
| 6️⃣ | **Human Authority** | *"When the stakes are high, does a human still get the final say?"* |

## Why this matters now

Three forces are converging:

1. **Regulators are catching up.** The EU AI Act, NIST AI RMF, and emerging US state laws all expect *operational* AI controls, not just paperwork.
2. **Insurers are pricing AI risk.** Carriers are starting to ask whether you have runtime governance — not whether you have a model card.
3. **The agents are getting more autonomous.** Tool use, multi-step planning, and agent-to-agent delegation mean the blast radius of a single bad decision is growing fast.

Doing nothing is itself a decision. ACR gives you a defensible, standards-aligned, open-source answer.

## How to evaluate ACR in 30 minutes

1. **Read this section.** ✅ You are most of the way there.
2. **Skim the [Six Pillars overview](docs)** — one paragraph per pillar.
3. **Look at the [NIST AI RMF mapping](docs/compliance/acr-nist-ai-rmf-mapping.md)** to see how it lines up with the framework you are already being measured against.
4. **Hand the engineering section below to your security architect.** They will be able to tell you in an afternoon whether this fits your stack.

> 💡 **Bottom line for the board:** ACR is the difference between *"we have an AI policy"* and *"we can prove our AI followed the policy on every one of last quarter's 14 million decisions, and we stopped it the three times it tried not to."*

---

# ⚙️ For Engineers

## TL;DR

**ACR is a policy-enforcing gateway for AI agents.** Every action an agent wants to take goes through `POST /acr/evaluate` and gets an `allow | deny | modify | escalate` decision. It's a single FastAPI service backed by Postgres + Redis + OPA, with a separate kill-switch sidecar, deployable on Kubernetes or `docker compose up`.

## 🚀 Quickstart (60 seconds)

```bash
git clone https://github.com/AdamDiStefanoAI/acr-standard.git
cd acr-standard/implementations/acr-control-plane
cp .env.example .env
# Local demo credentials only. Do not use these in production.
export OPERATOR_API_KEYS_JSON='{"dev-operator-key":{"subject":"dev-operator","roles":["agent_admin","approver","security_admin","auditor","killswitch_operator"]}}'
export SERVICE_OPERATOR_API_KEY=dev-operator-key
docker compose up --build
```

Migrations run automatically on startup (one-shot `acr-migrate` service). When the gateway is healthy:

```bash
curl http://localhost:8000/acr/health
# → {"status":"healthy","version":"1.1.0","env":"development"}

# Open the operator console
open http://localhost:8000/console
#   Operator API key:    dev-operator-key
#   Kill-switch secret:  killswitch_dev_secret_change_me
```

The health response `version` is configured runtime metadata (`settings.acr_version`), not the installed package version or a conformance declaration. The ordinary Compose image currently defaults to `1.1.0`; package releases are tracked separately.

That's it. You now have a working six-pillar control plane on your laptop.

## The hot path

```mermaid
sequenceDiagram
    autonumber
    participant A as Agent (JWT)
    participant G as ACR Gateway
    participant R as Redis
    participant DB as Postgres
    participant O as OPA
    participant K as Kill-switch (sidecar)
    participant H as Human approver

    A->>G: POST /acr/evaluate {action, params}
    G->>G: [0] JWT subject == agent_id
    G->>R: [1] is_killed?  (~0.5ms)
    G->>R: [1b] containment tier?
    G->>DB: [2] agent active + lifecycle ok
    G->>R: [3] rate-limit bucket
    G->>O: [4] Rego evaluate
    O-->>G: allow / deny / modify / escalate
    G->>G: [5] PII filter on params
    alt escalate
        G->>DB: create approval request
        G->>H: signed webhook
        G-->>A: 202 APPROVAL_PENDING
    else allow / deny / modify
        G-->>A: 200 / 403
    end
    Note over G,DB: BackgroundTasks (non-blocking):<br/>persist telemetry → drift sample →<br/>recompute drift score every N calls
    Note over K: Kill writes go through<br/>independent service.<br/>Reads are Redis-direct.
```

**Performance target:** p95 decision latency below 200ms is a design target, not a measured guarantee. The diagram summarizes the reference implementation, not proof of conformance. Under the normative standard (§11), inability to durably record required events MUST prevent high-risk protected execution, use alternate durable failure recording if available, and transition affected action classes to their documented safe-state if required evidence cannot be preserved. Asynchronous telemetry does not waive that gate.

## Architecture at a glance

```
                ┌─────────────────────────────────────────────────────────┐
                │                  ACR Control Plane                      │
                │                                                         │
   Agent ──JWT──▶│  FastAPI gateway  ──▶  OPA (Rego policies)             │
                │        │                                                │
                │        ├──▶ Postgres (agents, telemetry, approvals,     │
                │        │              drift baselines, policy releases) │
                │        │                                                │
                │        ├──▶ Redis (kill switch, rate limits, drift cache)│
                │        │                                                │
                │        └──▶ Background tasks (telemetry, drift, sweeps) │
                │                                                         │
                └─────────────────────────────────────────────────────────┘
                           │                              │
                           ▼                              ▼
                ┌──────────────────┐          ┌──────────────────────┐
                │ Kill-switch SVC  │          │   Human approvers    │
                │ (independent,    │          │ (HMAC-signed webhook │
                │  separate auth)  │          │  + operator console) │
                └──────────────────┘          └──────────────────────┘
```

## The six pillars (the engineering version)

| # | Pillar | Module | Backed by |
|---|---|---|---|
| 1 | **Identity & Purpose Binding** | `pillar1_identity/` | JWT (HS256/RS256/ES256, alg-pinned), Postgres `agents` table, lifecycle state machine (`draft → active → deprecated → retired`), lineage chain, capability tags, heartbeat sweep loop |
| 2 | **Behavioral Policy Enforcement** | `pillar2_policy/` | OPA via pooled `httpx.AsyncClient`, exponential-backoff retry, `aiobreaker` circuit breaker (5 fails / 60s → fail-secure deny). Policies authored in Rego with a draft → release → activate Studio lifecycle. |
| 3 | **Autonomy Drift Detection** | `pillar3_drift/` | Four signals — denial rate (0.35), call frequency (0.25), error rate (0.20), action diversity / Shannon entropy (0.20). Two-tier baselines: live ungoverned + versioned governed (`candidate → approved → active`) with dual-approval. |
| 4 | **Execution Observability** | `pillar4_observability/` | Structured `ACRTelemetryEvent` per request, correlation-ID indexed, OTLP + Prometheus exporters, SHA256-signed evidence bundles via `/acr/evidence/{correlation_id}`. |
| 5 | **Self-Healing Containment** | `pillar5_containment/` | Four graduated tiers — Throttle (0.60) → Restrict (0.75) → Isolate (0.90) → Kill (0.95). Kill writes go through an **independent sidecar** with its own `KILLSWITCH_SECRET` so a compromised gateway cannot silently re-enable agents. |
| 6 | **Human Authority** | `pillar6_authority/` | Persisted approval requests with configurable SLA (default 240m), background expiry loop, HMAC-SHA256-signed webhooks with idempotency keys, break-glass override (security_admin only, mandatory reason, WARN-logged). |

## Stack & ops posture

- **Language:** Python 3.11+, FastAPI, async SQLAlchemy 2 + asyncpg, Pydantic v2
- **Stores:** PostgreSQL (monthly partitioned `telemetry_events` and `drift_metrics`, 90-day retention sweep), Redis 7
- **Policy engine:** Open Policy Agent (Rego), with a draft/release/activate Policy Studio
- **Auth:** JWT for agents (alg allowlist), API keys *and* OIDC for operators, four RBAC roles (`agent_admin`, `security_admin`, `approver`, `auditor`)
- **Observability:** structlog JSON logs, OpenTelemetry OTLP traces + metrics, `/acr/metrics` Prometheus endpoint, SHA256-signed evidence bundles
- **Deployment:** `docker compose` for local, Kustomize for Kubernetes (HPAs, PDBs, NetworkPolicies, RBAC, init container that runs `alembic upgrade head` automatically)
- **CI:** GitHub Actions with lint, test, `pip-audit` security scanning

## Design choices that matter

- **Fail-secure everywhere.** OPA down → deny. Redis down → deny. Unexpected exception → deny. Never silently allow.
- **The kill switch is a separate process.** Reads are Redis-direct for the hot path; writes go through an independent service with its own secret. A compromised gateway cannot un-kill an agent.
- **Asynchronous work does not waive evidence requirements.** The reference implementation uses background work for telemetry and drift. Deployments must validate the §11 durable-evidence failure gate before claiming conformance; a latency target is not evidence that this gate is satisfied.
- **Policy is versioned.** Rego policies support allow, deny, modify, and escalate outcomes and are managed through the Policy Studio release lifecycle. Gateway safety checks also constrain execution. MODIFY requires a policy-supplied transformed payload; it is not permission to execute the original request unchanged.
- **Drift baselines have governance.** Without it, a slowly-misbehaving agent could simply re-baseline itself into "normal." Governed baselines require proposal → approval → activation by separate operators.
- **Migrations are automatic.** Both K8s and `docker compose` run `alembic upgrade head` before the gateway starts. You cannot forget to migrate.
- **Weak secrets are rejected at startup.** Production environments refuse to boot with default JWT keys, weak kill-switch secrets, or missing executor HMAC keys.

## The agent registry (Pillar 1, expanded)

The registry is more than a key-value store — it carries the metadata other pillars need to make smart decisions:

| Field | Why it exists |
|---|---|
| `agent_id`, `owner`, `purpose`, `risk_tier` | Identity and accountability |
| `version` | Audit trail of which version of an agent did what |
| `parent_agent_id` | Lineage for orchestrator → subagent relationships (non-FK so retirement preserves history) |
| `capabilities[]` | Declared skills, distinct from the tool allowlist — used by `/acr/agents/discover` |
| `lifecycle_state` | `draft → active → deprecated → retired` state machine, gates the evaluate hot path |
| `health_status` + `last_heartbeat_at` | Stale agents auto-downgrade to `unhealthy` via the sweep loop |
| `allowed_tools[]` / `forbidden_tools[]` | Authoritative tool boundaries enforced by Rego |
| `boundaries` | Rate, spend, region, and credential rotation limits |

## API surface (selected)

```
POST   /acr/evaluate                          # the hot path
POST   /acr/agents                            # register
GET    /acr/agents/discover?capability=...    # discovery
POST   /acr/agents/{id}/lifecycle             # state transitions
POST   /acr/agents/{id}/heartbeat             # health
GET    /acr/agents/{id}/lineage               # ancestor chain + children
POST   /acr/agents/{id}/token                 # issue short-lived JWT

GET    /acr/drift/{id}                        # current drift score
POST   /acr/drift/{id}/baseline/propose       # governed baseline workflow
POST   /acr/drift/{id}/baseline/{ver}/approve
POST   /acr/drift/{id}/baseline/{ver}/activate

GET    /acr/events/{correlation_id}           # decision chain replay
GET    /acr/evidence/{correlation_id}         # signed evidence bundle (SHA256)

POST   /acr/approvals/{id}/approve            # human authority
POST   /acr/approvals/{id}/override           # break-glass (WARN-logged)

GET    /acr/health  /acr/live  /acr/ready     # k8s probes
GET    /acr/metrics                           # Prometheus text
```

Full OpenAPI is served at `/docs` and `/redoc` (operator-authenticated outside development).

## Repo layout

```
acr-standard/
├── docs/                            ← standard spec (the "why")
├── implementations/
│   └── acr-control-plane/           ← runnable reference implementation
│       ├── src/acr/
│       │   ├── pillar1_identity/    ← registry, lifecycle, lineage, JWT
│       │   ├── pillar2_policy/      ← OPA client, circuit breaker, output filter
│       │   ├── pillar3_drift/       ← signals, baselines, governance
│       │   ├── pillar4_observability/ ← telemetry, OTLP, evidence bundles
│       │   ├── pillar5_containment/ ← graduated tiers, kill switch
│       │   ├── pillar6_authority/   ← approvals, webhooks, override
│       │   ├── policy_studio/       ← draft → release → activate lifecycle
│       │   ├── gateway/             ← FastAPI router, middleware, executor
│       │   ├── operator_console/    ← read-only web UI
│       │   └── db/migrations/       ← Alembic (head: 0012)
│       ├── policies/                ← Rego policies + tests
│       ├── deploy/k8s/base/         ← Kustomize manifests
│       ├── tests/                   ← 160+ unit + integration tests
│       ├── docker-compose.yml
│       └── Dockerfile{,.killswitch}
└── README.md                         ← you are here
```

## Where to look first if you're reading the code

1. **`src/acr/main.py`** — application wiring, lifespan, background loops
2. **`src/acr/gateway/router.py`** — the `/acr/evaluate` hot path
3. **`src/acr/pillar2_policy/engine.py`** — the OPA client with retry + circuit breaker
4. **`src/acr/pillar5_containment/graduated.py`** — the four-tier containment ladder
5. **`policies/`** — the Rego policies that actually make the allow/deny calls

## Compliance mappings

| Standard | Mapping |
|---|---|
| 🇺🇸 NIST AI RMF | [`docs/compliance/acr-nist-ai-rmf-mapping.md`](docs/compliance/acr-nist-ai-rmf-mapping.md) |
| 🌍 ISO/IEC 42001 | [`docs/compliance/`](docs/compliance) |
| 🔒 SOC 2 | [`docs/compliance/`](docs/compliance) |
| 🛡️ Threat model | [`docs/security/acr-strike-threat-model.md`](docs/security/acr-strike-threat-model.md) |

## Project status

The control plane is a reference implementation for evaluation and contribution. Production use requires deployment-specific security review, hardening, and validation; the included examples and development credentials are for isolated local use.

- ✅ Six pillars implemented and tested
- ✅ Production-grade Kubernetes manifests
- ✅ Automated migrations (no manual `alembic upgrade head`)
- ✅ Compliance mappings for NIST AI RMF, ISO 42001, SOC 2
- ✅ 160+ unit tests, evidence-bundle integration tests
- 📋 [Roadmap](./ROADMAP.md) · [Changelog](./CHANGELOG.md) · [Adoption guide](./ADOPTION.md)

## Captured runtime evidence

See the [evidence walkthrough](docs/evidence-walkthrough.md) for actual synthetic allow/deny responses, observed execution counts, and matching captured ALLOW and DENY events/exports. The limits of this disposable test are explicit.

New to the control flow? Read the [plain-language decision walkthrough](docs/decisions-explained.md) from guarded request through policy, filtering, approval, and evidence.

## Contributing

Start with the [coding contribution guide](CONTRIBUTING.md#code-contributions) for setup, tests, and the repository map. Use [GitHub Issues](https://github.com/AdamDiStefanoAI/acr-standard/issues) for questions, bugs, and design proposals. We welcome focused PRs. See [`CONTRIBUTING.md`](./CONTRIBUTING.md), [`GOVERNANCE.md`](./GOVERNANCE.md), and [`CODE_OF_CONDUCT.md`](./CODE_OF_CONDUCT.md). Security issues: [`SECURITY.md`](./SECURITY.md).

---

<div align="center">

## **Like OWASP for AppSec. Like MITRE ATT&CK for threats.**
## **ACR is the reference architecture for runtime AI governance.**

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg?style=for-the-badge)](LICENSE)
[![Adopt ACR](https://img.shields.io/badge/Adopt-ACR-00d4ff.svg?style=for-the-badge)](./ADOPTION.md)
[![Star on GitHub](https://img.shields.io/github/stars/AdamDiStefanoAI/acr-standard?style=for-the-badge&logo=github)](https://github.com/AdamDiStefanoAI/acr-standard)

**[runtimecontrol.io/control-plane](https://runtimecontrol.io/control-plane)**

</div>
