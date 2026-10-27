# ACR Control Plane

**A runtime control plane for AI agents that take real actions.**

This is the reference control plane for the [ACR Framework](https://github.com/AdamDiStefanoAI/acr-standard): a governance gateway that sits between autonomous agents and the systems they want to touch.

If agents are going to reach customer data, ticketing systems, production infrastructure, payment flows, or regulated workflows, then logs and prompt rules are not enough. You need a real enforcement point on the execution path.

This repo is that reference implementation.

## The 30-second version

```bash
pip install acr-control-plane
```

```python
from acr.sdk import ACRClient, guard_tool
from acr.pillar1_identity.models import AgentRegisterRequest

client = ACRClient(base_url="http://localhost:8000", operator_api_key="dev-operator-key")
client.ensure_agent_registered(AgentRegisterRequest(
    agent_id="support-bot",
    owner="support@example.com",
    purpose="Handle governed support actions",
    allowed_tools=["refund_customer"],
    forbidden_tools=["delete_customer"],
))
session = client.issue_agent_session("support-bot")

def refund_customer(customer_id: str, amount_usd: float) -> str:
    """Issue a refund to a customer."""
    return f"refunded ${amount_usd} to {customer_id}"

# Wrap any function: ACR authorizes it BEFORE it executes.
refund_customer = guard_tool(refund_customer, session=session)

refund_customer("cus_123", 25.00)   # allowed: runs, logged, attributed
```

`guard_tool` wraps any Python function so ACR authorizes it **before it executes**.
Denied actions raise `ACRDeniedError` and never run. Escalations return a
202 approval request instead of executing. Every decision lands in the
evidence log with a correlation ID.

Async tools: `guard_async_tool`. LangChain/LangGraph: `build_langchain_tool`.
No gateway on your laptop yet? Try the [no-Docker quickstart](examples/quickstart_no_docker.py)
to run this exact pattern against a mocked gateway in 60 seconds, or
[run the full control plane](#quick-start) with Docker Compose.

![60-second demo: pip install, an allowed action runs, a denied action is blocked before execution](quickstart-demo.gif)

## Why This Exists

Most agent stacks are optimized for capability:
- better planning
- better tool use
- better memory
- better autonomy

Most are not optimized for control.

That leaves a dangerous gap:
- agents can act faster than humans can review
- prompts and app logic are weak enforcement boundaries
- direct tool access can bypass governance entirely
- security teams often get telemetry after the fact instead of a hard stop before execution

The ACR Control Plane closes that gap with:
- identity binding
- policy enforcement
- approval workflows
- drift detection
- kill-switch containment
- forensic evidence export

## What It Proves

Every agent action request flows through a governed decision pipeline before it is allowed, denied, or escalated.

```text
Agent Runtime
    |
    v
ACR Gateway
    |
    +--> Identity and purpose binding
    +--> Behavioral policy enforcement
    +--> Output controls
    +--> Telemetry and evidence
    +--> Drift detection
    +--> Human approval
    +--> Kill switch containment
    |
    v
Allowed enterprise action
```

This gives you a hard boundary between:
- what an agent wants to do
- what your organization is willing to let it do

The repo now demonstrates four proof points that matter to real adopters:
- runtime policy decisions on the hot path
- bypass-resistant downstream execution with payload-bound authorization
- gateway-minted short-lived brokered credentials for executors
- security and secret-management guardrails around the control plane itself

## Why It’s Different

Most "agent governance" products stop at dashboards, evals, or prompt wrappers.

This project is opinionated in a more operational way:
- **Fail-secure by default.** If a critical dependency breaks, the safe answer is deny.
- **Policy as code.** Enforcement is not trapped in prompts or UI rules. It lives in versioned OPA/Rego policy.
- **Runtime-first.** This is designed for live action requests, not just offline evaluation.
- **Operator-ready.** There is a console for approvals, keys, policy drafting, release activation, drift inspection, and containment actions.
- **Forensics included.** Evidence bundles can be exported per correlation ID with manifest, events, and checksums.
- **Bypass-aware.** Downstream executors can verify short-lived gateway authorization and brokered credentials before they run anything.
- **Enterprise-shaped.** JWTs, OIDC-ready operator auth, API keys, Redis, Postgres, OPA, OpenTelemetry, Docker, Kubernetes manifests.

## The Six Control Pillars

| Pillar | Control | Why it matters |
|---|---|---|
| 1 | Identity and Purpose Binding | Ensures the caller is a registered agent operating within declared purpose and boundaries |
| 2 | Behavioral Policy Enforcement | Applies allow, deny, and escalate logic before execution |
| 3 | Autonomy Drift Detection | Detects behavior deviating from expected baselines |
| 4 | Execution Observability | Captures decision telemetry, traces, and evidence |
| 5 | Self-Healing and Containment | Supports kill-switch and graduated response patterns |
| 6 | Human Authority | Routes risky actions into approvals, overrides, and SLA-backed review |

## What You Can Demo In Minutes

With the included stack, you can:
- register an agent
- issue a short-lived JWT
- evaluate allowed and forbidden tool calls
- trigger approval escalation for risky actions
- inspect telemetry in the operator console
- generate policy drafts and publish policy releases
- activate a live bundle alias for OPA discovery
- export evidence for a single run

The included sample agent shows the control plane denying unsafe actions and escalating high-risk ones.

There is now an official [SDK and adapter guide](docs/sdk.md) covering:

- a Python SDK
- a LangGraph/LangChain-style tool guard
- a TypeScript SDK

There is also a runnable [protected executor example](examples/protected_executor/README.md) that verifies both `X-ACR-Execution-Token` and `X-ACR-Brokered-Credential`, so downstream services can reject direct-bypass requests that were not explicitly authorized by the gateway.

For OpenAI Agents SDK integrations, see the [OpenAI Agents SDK guard example](examples/openai_guard_example.py), which shows how to wrap tools with ACR’s `guard_tool` using a simple adapter pattern.

For workflow builders and orchestration tools, there is now an explicit [orchestrator integration guide](docs/orchestrators.md) plus an [n8n reference example](examples/n8n/README.md) showing how to put ACR underneath the workflow layer instead of relying on optional user behavior.

## Quick Start

### 1. Start the stack

Run from `implementations/acr-control-plane/` in a Git checkout. Docker Compose v2 is required. The following credentials are for an isolated local demo only.

```bash
cp .env.example .env
export OPERATOR_API_KEYS_JSON='{"dev-operator-key":{"subject":"dev-operator","roles":["agent_admin","approver","security_admin","auditor","killswitch_operator"]}}'
export SERVICE_OPERATOR_API_KEY=dev-operator-key
docker compose up --build
```

Services:

| Service | Port | Purpose |
|---|---|---|
| `acr-gateway` | `8000` | Main control plane |
| `acr-killswitch` | `8443` | Independent containment service |
| `opa` | `8181` | Policy engine |
| `postgres` | `5432` | Persistent state |
| `redis` | `6379` | cache, rate limits, coordination |

### 2. Verify health

```bash
curl http://localhost:8000/acr/health
```

Expected:

```json
{"status":"healthy","version":"1.1.0","env":"development"}
```

The health response `version` is configured runtime metadata (`settings.acr_version`), not the installed package version or a conformance declaration. The ordinary Compose image currently defaults to `1.1.0`; package releases are tracked separately.

### 3. Open the operator console

Visit [http://localhost:8000/console](http://localhost:8000/console)

Use:
- Operator API key: `dev-operator-key`
- Kill switch secret: `killswitch_dev_secret_change_me`

Inside the console you can:
- create and rotate operator keys
- register and manage agents
- draft policy packages
- simulate policy decisions
- publish and activate releases
- review approvals
- inspect events and drift
- trigger containment

### 4. Run the sample agent

In a second terminal, change to `implementations/acr-control-plane/`. Use Python 3.11 or 3.12 and install the package so the sample can import `acr.sdk`:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e .
export ACR_OPERATOR_API_KEY=dev-operator-key
python examples/sample_agent/agent.py
```

See the [sample agent README](examples/sample_agent/README.md) for the full setup and Windows activation command.

The sample flow demonstrates:
1. agent registration
2. normal allowed actions
3. denied dangerous actions
4. escalated high-risk actions

## Quickstart troubleshooting

These are diagnostic checks for the documented local Compose path, not a claim that every host setup was tested. Use only an isolated development stack; do not delete shared volumes or stop unrelated services.

| Symptom | Likely cause / check | Next step |
|---|---|---|
| `port is already allocated` / `address already in use` | Another service owns a published port. Inspect `docker compose ps` and the ports in `docker-compose.yml`. | Stop only your conflicting local demo, or choose unused host ports and update client URLs consistently. |
| Build or container exits with `OOMKilled`, exit 137, or an explicit memory allocation error | Docker's available memory may be exhausted. Inspect `docker compose ps -a`, service logs and Docker resource settings; exit 137 alone is not proof of OOM. | Free local resources or adjust Docker's memory allocation yourself, then retry the disposable stack. Do not weaken application security checks. |
| First build appears slow | Initial image pulls and dependency installation may take longer than cached runs. Watch `docker compose up --build` output. | Keep the build output visible; investigate the specific download/build error rather than assuming a fixed 60-second completion time. No portable first-build duration is guaranteed. |
| Gateway health request fails | Gateway may still be starting, migrations may have failed, or a dependency may be unhealthy. | Run `docker compose ps -a` and `docker compose logs --tail=100 acr-migrate acr-gateway postgres redis opa`; resolve the reported failure, then retry `curl --fail http://localhost:8000/acr/health`. |
| Operator request returns 401 | The configured operator key and client key may differ, or environment variables were set in another shell. | Follow the sample-agent setup, keep the local key consistent and recreate the affected demo containers after environment changes (`docker compose restart` does not apply new environment values). Never paste production secrets into an issue. |

The disposable full-stack CI run validates its own fixture/override setup. A separate fresh-runner check follows the ordinary README path; see the [newcomer validation record](../../docs/newcomer-validation.md) for the successful run, original failures and host/browser limitations.

See the [captured evidence walkthrough](../../docs/evidence-walkthrough.md) for real synthetic allow/deny responses, observed tool effects, and the limits of the captured audit chain.

## Core API Surface

Full API docs live in [docs/api.md](docs/api.md).
Operational adoption guidance for workflow tools lives in [docs/orchestrators.md](docs/orchestrators.md).

The main endpoints are:

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/acr/evaluate` | Evaluate an agent action request |
| `POST` | `/acr/agents` | Register a new agent |
| `POST` | `/acr/agents/{agent_id}/token` | Issue an agent JWT |
| `GET` | `/acr/approvals` | Review pending approvals |
| `GET` | `/acr/events` | Query telemetry events |
| `GET` | `/acr/evidence/{correlation_id}` | Export a run evidence bundle |
| `GET` | `/acr/drift/{agent_id}` | Inspect drift posture |
| `POST` | `/acr/containment/kill` | Trigger containment |

## Security Posture

This repo is designed around the assumption that agent systems eventually become high-impact systems.

That shows up in the implementation:
- operator endpoints require authenticated access
- docs and console can be gated outside development
- readiness responses can be sanitized for non-sensitive status output
- JWT issuance is rate-limited
- secrets are rejected in non-development environments if they are weak defaults
- production secret generation and CI secret-hygiene checks are included
- policy distribution is separated from operator control surfaces
- downstream executors can require short-lived gateway-issued execution authorization tied to the exact payload
- downstream executors can require short-lived brokered credentials with audience and scope claims
- evidence export supports incident response and auditability

## Enterprise Roadmap

The next hardening steps are tracked in [docs/enterprise-roadmap.md](docs/enterprise-roadmap.md).

Current highlights:
- bypass-resistant downstream execution is implemented as a reference pattern
- the repo includes a dedicated security workflow for CodeQL, Semgrep, Gitleaks, Trivy, and SBOM generation
- production secret generation and secret-hygiene checks are in place
- brokered downstream credential minting is implemented
- release provenance and signing guidance now live in [docs/provenance-and-verification.md](docs/provenance-and-verification.md)
- the enterprise review artifacts now live in [docs/compliance/README.md](docs/compliance/README.md)
- the blessed production deployment path now lives in [deploy/k8s/overlays/production/README.md](deploy/k8s/overlays/production/README.md)
- official Python and TypeScript SDKs now live in [docs/sdk.md](docs/sdk.md)
- the next major gap is reliability semantics under dependency failure

## Architecture

```text
Agent Runtime
  |
  | POST /acr/evaluate
  v
ACR Control Plane
  |
  +--> Pillar 1: Identity
  +--> Pillar 2: Policy
  +--> Pillar 3: Drift
  +--> Pillar 4: Observability
  +--> Pillar 5: Containment
  +--> Pillar 6: Authority
  |
  v
Enterprise tools, APIs, data, and workflows
```

Target synchronous path:

```text
Identity -> Policy -> Output controls -> Response
```

Background tasks handle telemetry persistence, drift work, and approval lifecycle without bloating the hot path.

## Local Development

Follow the repository [coding contribution guide](../../CONTRIBUTING.md#code-contributions) for the supported setup, unit/integration test separation, and PR checklist. Commands below run from this implementation directory.

### Install

```bash
pip install -e ".[dev]"
```

### Generate production secrets

```bash
python scripts/generate_secrets.py > .env.production
```

Use `.env.production.example` as the non-dev template and store the generated values in your secret manager rather than committing them.

### Run tests

```bash
ACR_ENV=test python -m pytest tests/ --ignore=tests/integration -v --cov=src/acr --cov-report=term-missing
```

### Run without the full Docker stack

```bash
docker-compose up postgres redis opa acr-killswitch

DATABASE_URL=postgresql+asyncpg://acr:acr_dev_password@localhost:5432/acr_control_plane \
REDIS_URL=redis://localhost:6379/0 \
OPA_URL=http://localhost:8181 \
KILLSWITCH_URL=http://localhost:8443 \
OPERATOR_API_KEYS_JSON='{"dev-operator-key":{"subject":"dev-operator","roles":["agent_admin","approver","security_admin","auditor","killswitch_operator"]}}' \
SERVICE_OPERATOR_API_KEY=dev-operator-key \
uvicorn acr.main:app --reload
```

### Test policies

```bash
opa test policies/ -v
```

## Project Layout

```text
src/acr/
  main.py                     FastAPI entrypoint
  gateway/                    request evaluation pipeline
  pillar1_identity/           agent registry and token issuance
  pillar2_policy/             OPA policy integration
  pillar3_drift/              baseline and anomaly scoring
  pillar4_observability/      telemetry and evidence
  pillar5_containment/        kill switch and containment flows
  pillar6_authority/          approval queue and override logic
  policy_studio/              policy drafting and release management
  operator_console/           operator UI
  db/                         models and migrations
```

## Who This Is For

This is a strong fit if you are:
- building agentic products that can take actions, not just answer questions
- trying to get security, compliance, and platform teams aligned on one control layer
- experimenting with human-in-the-loop approval for risky workflows
- looking for a real reference architecture for AI runtime governance

## If You’re Evaluating It Internally

Start with this question:

**If one of your agents tried to refund money, delete records, exfiltrate data, or hit a sensitive internal API right now, where would the hard stop actually live?**

If the answer is "the prompt," "the app code," or "we’d catch it in logs," this project will probably feel uncomfortably relevant.

## License

Apache 2.0. See [LICENSE](LICENSE).

Based on the [ACR Framework specification](https://github.com/AdamDiStefanoAI/acr-standard).
