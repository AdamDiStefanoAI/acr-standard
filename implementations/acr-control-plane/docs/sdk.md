# ACR SDKs and Adapters

This repo now includes official client surfaces for integrating ACR into agent runtimes and workflow tooling.

## Python SDK

Import from:

```python
from acr.sdk import ACRClient, AsyncACRClient
```

What it covers:

- agent registration
- token issuance
- runtime calls to `POST /acr/evaluate`
- bound per-agent sessions
- typed request and decision models

Core modules:

- [client.py](../src/acr/sdk/client.py)
- [errors.py](../src/acr/sdk/errors.py)
- [langgraph.py](../src/acr/sdk/langgraph.py)

Basic example:

```python
from acr.pillar1_identity.models import AgentRegisterRequest
from acr.sdk import ACRClient

client = ACRClient(
    base_url="https://acr.example.com",
    operator_api_key="operator-key",
)

client.ensure_agent_registered(
    AgentRegisterRequest(
        agent_id="support-bot",
        owner="support@example.com",
        purpose="Handle governed support actions",
        allowed_tools=["send_email", "create_ticket"],
    )
)

session = client.issue_agent_session("support-bot")
result = session.evaluate_action(
    tool_name="send_email",
    parameters={"to": "alice@example.com", "subject": "Update", "body": "Resolved"},
    context={"session_id": "sess-123"},
)
```

## LangGraph Adapter

For a credential-free compiled graph covering allow, deny, and escalation, see the
[offline refund example](../examples/langgraph_refund/README.md). It uses synthetic
HTTP decisions and fake in-memory refunds, not a payment service or live policy engine.

The Python SDK also includes a real adapter layer for LangGraph/LangChain-style tools.

**Verification status (2026-11-23, v1.5.0 WS5):** the adapter is verified
against langchain-core 1.8.4 and langgraph 1.2.24, including streaming
(sync and async), native async tool dispatch, and LangGraph retry paths;
`pip-audit` reports no known vulnerabilities for the current dependency
family. (The 2026-10-25 not-audit-clean limitation referred to the legacy
pre-1.0 example dependency family and no longer applies; the `integrations`
extra now pins the verified 1.x line.) The base `pip install
acr-control-plane` path does not install them. The plain `guard_tool` and
`guard_async_tool` wrappers do not require LangChain.

One retry subtlety matters: LangGraph's default `RetryPolicy` does not
retry `RuntimeError` subclasses, so an ACR denial is final unless a graph
opts into retrying it explicitly — and even then every retry is a fresh
ACR evaluation, never a replay of the denied call.

Use:

- `guard_tool(...)`
- `guard_async_tool(...)`
- `build_langchain_tool(...)`

Example:

```python
from acr.sdk import ACRClient, guard_tool

client = ACRClient(base_url="https://acr.example.com", operator_api_key="operator-key")
session = client.issue_agent_session("refund-agent")

def issue_refund(customer_id: str, amount: float) -> dict:
    return {"status": "queued", "customer_id": customer_id, "amount": amount}

guarded_refund = guard_tool(
    issue_refund,
    session=session,
    context_builder=lambda params: {"workflow": "refund_graph"},
    intent_builder=lambda params: {
        "goal": "Resolve customer issue with a refund",
        "justification": f"Refund {params['amount']} to customer {params['customer_id']}",
    },
)
```

That wrapper will:

- call ACR before the tool executes
- raise on `deny`
- raise on `escalate`
- apply modified parameters on `modify`
- return gateway-managed execution output when configured not to execute locally

## CrewAI Adapter

`acr.sdk.crewai` guards tools built with CrewAI's `@tool` decorator without
hand-written wrapper functions:

- `guard_crewai_tool(tool, session=...)` — guard one existing tool; returns a
  CrewAI tool with the same name and description.
- `guard_crewai_tools([...], session=...)` — guard a whole tool list at once.

```python
from crewai.tools import tool
from acr.sdk import ACRClient
from acr.sdk.crewai import guard_crewai_tool

session = ACRClient(base_url="https://acr.example.com", operator_api_key="<redacted>").issue_agent_session("ops-agent")

@tool("restart_service")
def restart_service(service_name: str) -> str:
    """Restart a named service."""
    return f"restarted {service_name}"

restart_service = guard_crewai_tool(restart_service, session=session)
```

CrewAI itself is supplied by your agent application; the adapter imports it
only when rebuilding the guarded tool, and otherwise returns the guarded
plain function. Class-based `BaseTool` subclasses are not rewrappable
without losing their schema — guard the function the tool calls instead.
See the [CrewAI guard example](../examples/crewai_guard_example.py).

## OpenAI Agents SDK Adapter

`acr.sdk.openai_agents` guards tools for the OpenAI Agents SDK at the same
parity as the CrewAI adapter:

- `guard_openai_tool(fn, session=...)` — guard one plain Python function (or
  a CrewAI-style tool object exposing one); returns an Agents SDK
  `FunctionTool` with the same name and description.
- `guard_openai_tools([...], session=...)` — guard a whole tool list at once.

```python
from acr.sdk import ACRClient
from acr.sdk.openai_agents import guard_openai_tool

session = ACRClient(base_url="https://acr.example.com", operator_api_key="<redacted>").issue_agent_session("ops-agent")

def restart_service(service_name: str) -> str:
    """Restart a named service."""
    return f"restarted {service_name}"

restart_tool = guard_openai_tool(restart_service, session=session)
# hand restart_tool to your Agent(tools=[...]) as usual
```

The guarded tool is built with `failure_error_function=None`, so a deny or
escalate decision raises `ACRDeniedError` / `ACREscalatedError` out of the
tool call instead of being converted into a model-visible error string the
agent could talk its way around. The exception carries the full evaluate
response — `correlation_id` (and `approval_request_id` on escalate) is the
receipt binding for the recorded decision. As with the other adapters, a
`modify` decision applies the transformed parameters and a gateway-managed
execution result short-circuits local execution.

The Agents SDK itself is supplied by your agent application; the adapter
imports it only when building the `FunctionTool`, and otherwise returns the
guarded plain function. Guard plain functions (or `@function_tool`-style
callables before wrapping): an already-built `FunctionTool` does not expose
its underlying function and cannot be re-wrapped. Verified against
openai-agents 0.25.0 (2026-11-23, v1.5.0 WS5). For a session-based wiring
without the adapter, see the [OpenAI guard
example](../examples/openai_guard_example.py).

The Python SDK rejects ALLOW/MODIFY on non-200 evaluation responses. A MODIFY
response must include an explicit replacement action and parameters for the
requested tool; missing transformations and changed tool names raise an SDK
error rather than executing the original call. An explicitly empty parameter
object remains valid and follows the wrapped function's normal default-argument
behavior. These checks do not authenticate a compromised gateway or provide
approval replay/concurrency protection.

## TypeScript SDK

The TypeScript package lives at:

- [sdks/typescript/README.md](../sdks/typescript/README.md)

It mirrors the same concepts:

- `ACRClient`
- `ACRAgentSession`
- `evaluate(...)`
- `evaluateAction(...)`
- typed decision and error objects

## Piloting a Guarded Agent in Observe Mode

Whichever adapter you use, the agent behind it can be registered in
`observe` enforcement mode: evaluations run and are recorded exactly as
in enforce mode, the call proceeds, and the response carries
`enforcement_mode: "observe"` with the `would_be_decision` for your
logs. It is the recommended way to pilot ACR against real traffic
before enforcing. See [Piloting with Observe Mode](piloting-observe-mode.md)
for the 30-day pilot playbook and the observe report.

## Why This Matters

The goal is not to make ACR optional glue code.

The goal is to make the control plane easy to place at the action boundary, so teams can integrate it into their existing runtime without re-implementing auth, evaluation payloads, or decision handling every time.
