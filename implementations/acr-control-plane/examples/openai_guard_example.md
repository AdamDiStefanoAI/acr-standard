# OpenAI Agents SDK guard example

This example keeps the contributor's balance lookup / blocked account-deletion
scenario. All business-tool effects are in-memory lists: it never accesses a
customer account, sends a model request, or needs an OpenAI API key.

## 1. Mock gateway, plain guarded calls

From a Git checkout's **repository root**, with Python 3.11 or 3.12:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e implementations/acr-control-plane
python implementations/acr-control-plane/examples/openai_guard_example.py
```

This path needs no optional framework. It prints `MOCK gateway` and
`Side effects: balances=1, deletions=0`. The mock does not prove real policy
evaluation, authentication, persistence, approval handling, or audit evidence.

## 2. Real SDK tool dispatch, still a mock gateway

In that same environment:

```bash
python -m pip install openai-agents==0.24.0
OPENAI_AGENTS_DISABLE_TRACING=1 python implementations/acr-control-plane/examples/openai_guard_example.py --agents
```

The example registers only ACR-guarded callables on a real `Agent`, then invokes
its `FunctionTool` callbacks with deterministic arguments. It does not call
`Runner` or a model. `failure_error_function=None` propagates ACR denial and
escalation rather than converting them to ordinary tool-result text. A missing,
incompatible, or broken SDK is an error in this mode, not a successful skip.

Expected: the same execution counts and `Real SDK tool dispatch; no model run.`
This is SDK tool-boundary coverage, not a complete model/agent-loop test.

## 3. Real disposable quickstart gateway

Use an isolated local stack only. **Disable gateway-side execution before
starting it**: these guarded tools execute locally, and enabling execution in
both places could execute an action twice. No existing production or shared
gateway is appropriate for this demo. The example only accepts loopback URLs.
As an additional safeguard, the guards use `execute_locally_on_allow=False`:
if the gateway nevertheless returns an execution result, the tool will not run
locally again and the demo's local execution-count check will fail.

In a separate terminal, from the repository root:

```bash
cd implementations/acr-control-plane
cp .env.example .env
export OPERATOR_API_KEYS_JSON='{"dev-operator-key":{"subject":"dev-operator","roles":["agent_admin","approver","security_admin","auditor","killswitch_operator"]}}'
export SERVICE_OPERATOR_API_KEY=dev-operator-key
export EXECUTE_ALLOWED_ACTIONS=false
export COMPOSE_PROJECT_NAME=acr-openai-demo
docker compose up --build
```

These are the [sample-agent quickstart](sample_agent/README.md) steps with
explicit local execution mode and a separate Compose project. Use unused local
ports; do not start over an existing stack. Wait for
`curl --fail http://localhost:8000/acr/health` to succeed.

In the first terminal, with the environment from steps 1 and 2 active:

```bash
export ACR_OPERATOR_API_KEY=dev-operator-key
export ACR_BASE_URL=http://localhost:8000
OPENAI_AGENTS_DISABLE_TRACING=1 python implementations/acr-control-plane/examples/openai_guard_example.py --live --agents
```

Expected: `LIVE disposable local gateway`, real SDK dispatch, and exactly
`Side effects: balances=1, deletions=0`. The client registers the synthetic
`openai-guard-demo` agent, obtains its token, and asks the actual gateway for
each decision. A denial must occur; unexpected permission or execution counts
terminate with an error. Existing demo registration with different tool rules
is rejected rather than silently changed.

After stopping the foreground stack, remove **only this disposable project**:

```bash
COMPOSE_PROJECT_NAME=acr-openai-demo docker compose down --volumes --remove-orphans
```

Run that cleanup from `implementations/acr-control-plane`. The development key
is public demo configuration, never a production credential. On PowerShell,
activate `.venv\Scripts\Activate.ps1` and use `$env:NAME = 'value'` for environment
variables instead of `export` / inline assignments.

## Offline regression checks

From `implementations/acr-control-plane`, after installing `.[dev]` and the
optional SDK version above:

```bash
ACR_ENV=test OPENAI_AGENTS_DISABLE_TRACING=1 python -m pytest tests/test_contributor_guard_examples.py -v
```

The tests observe action counts and payloads for ALLOW, DENY, MODIFY, ESCALATE,
and transport failure; they also inject broken guards so a misleadingly
successful example cannot pass. They use synthetic gateway responses, not a
live gateway. If the optional SDK is absent, its dispatch cases are skipped;
skips are not evidence of a working integration.

The `ACR contributor examples` hosted workflow installs the exact optional SDK,
rejects skipped offline checks, verifies gateway-side execution is disabled, and
runs the documented live command. It also checks all four decisions through real
SDK callbacks, using the quickstart's actual policies and synthetic in-memory
tools. Its Compose override only limits host ports to loopback and disables
external executors/telemetry; it does not replace the gateway or OPA with mocks.
Evidence includes requested/modified payloads, counts, correlation IDs and the
pending approval ID. Approval resolution and durable audit verification are
outside this example's scope. A configured workflow is not proof it has passed;
check its results for the exact revision before accepting the live path.
