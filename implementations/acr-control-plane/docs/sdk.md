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

The Python SDK also includes a real adapter layer for LangGraph/LangChain-style tools.

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

## Why This Matters

The goal is not to make ACR optional glue code.

The goal is to make the control plane easy to place at the action boundary, so teams can integrate it into their existing runtime without re-implementing auth, evaluation payloads, or decision handling every time.
