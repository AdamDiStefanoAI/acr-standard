"""
OpenAI Agents SDK — guard_tool example.

Shows how to wrap a local tool with ACR's guard_tool and a simple adapter
pattern for registering the guarded tool with an OpenAI Agents-style SDK.

Run:

    pip install -e implementations/acr-control-plane httpx
    python implementations/acr-control-plane/examples/openai_guard_example.py

Notes:
- The OpenAI Agents SDK import is optional: if it's not installed the example
  still demonstrates the guarded-call pattern and prints guidance.
- Replace the "register tool" adapter below with the real registration call
  your Agents SDK expects.
"""

from __future__ import annotations

import json
from typing import Any

import httpx

from acr.sdk import ACRAgentSession, ACRClient, ACRDeniedError, guard_tool


def _mock_gateway(request: httpx.Request) -> httpx.Response:
    """Simple mock policy: allow 'fetch_balance', deny 'delete_account'."""
    body = json.loads(request.content)
    tool_name = body.get("action", {}).get("tool_name", "")
    if tool_name == "delete_account":
        return httpx.Response(
            200,
            json={
                "decision": "deny",
                "reason": "delete_account is forbidden for this demo agent",
                "correlation_id": "demo-corr-deny",
            },
        )
    return httpx.Response(
        200,
        json={
            "decision": "allow",
            "reason": f"{tool_name} allowed",
            "correlation_id": "demo-corr-allow",
            "latency_ms": 5,
        },
    )


def main() -> None:
    # 1) Create a client that talks to a "mock" gateway (no Docker required)
    transport = httpx.MockTransport(_mock_gateway)
    client = ACRClient(
        base_url="http://gateway.local",
        operator_api_key="demo-key",
        client=httpx.Client(transport=transport, base_url="http://gateway.local"),
    )
    session = ACRAgentSession(
        client=client, agent_id="demo-agent", access_token="demo-token"
    )

    # 2) A plain Python tool (what the agent runtime would call)
    def fetch_balance(customer_id: str) -> dict[str, Any]:
        """Return a fake balance for a customer."""
        return {"customer_id": customer_id, "balance_usd": 42.5}

    def delete_account(customer_id: str) -> dict[str, Any]:
        """Dangerous example that should be denied by policy."""
        return {"status": "deleted", "customer_id": customer_id}

    # 3) Wrap the local functions with guard_tool
    guarded_fetch_balance = guard_tool(
        fetch_balance, session=session, tool_name="fetch_balance"
    )
    guarded_delete_account = guard_tool(
        delete_account, session=session, tool_name="delete_account"
    )

    # 4) Direct usage demonstration (what happens when an agent runtime invokes the function)
    print("Manual (guarded) call: fetch_balance -> should be allowed")
    print(guarded_fetch_balance("C-100"))

    print("\nManual (guarded) call: delete_account -> should be denied")
    try:
        guarded_delete_account("C-100")
    except ACRDeniedError as exc:
        print(f"Denied as expected: {exc}")

    # 5) Adapter with the signature expected by OpenAI Agents SDK function tools.
    def openai_fetch_balance_tool(customer_id: str) -> dict[str, Any]:
        """Fetch a balance through the ACR-guarded local tool."""
        return guarded_fetch_balance(customer_id=customer_id)

    # 6) The SDK is optional. When available, expose the guarded adapter as an
    # OpenAI function tool and add it to an Agent; no model run is started.
    try:
        import agents
    except ImportError as import_exc:
        print(
            "OpenAI Agents SDK is not installed (or its `agents` import is unavailable); "
            "skipping SDK registration.\n"
            "The guarded adapter `openai_fetch_balance_tool` is ready to register when "
            "the SDK is available."
        )
        print(f"Import detail: {import_exc}")
    else:
        agent_class = getattr(agents, "Agent", None)
        function_tool = getattr(agents, "function_tool", None)
        if not callable(agent_class) or not callable(function_tool):
            print(
                "The `agents` package is installed, but its Agent or function_tool "
                "registration API is unavailable; registration demo skipped."
            )
        else:
            try:
                sdk_tool = function_tool(openai_fetch_balance_tool)
                agent_class(
                    name="ACR guarded example",
                    instructions="Use the guarded tool to fetch a customer balance.",
                    tools=[sdk_tool],
                )
            except Exception as registration_exc:
                print(
                    "OpenAI Agents SDK was imported, but tool registration failed; "
                    "registration demo skipped."
                )
                print(f"Registration detail: {registration_exc}")
            else:
                print(
                    "Registered the guarded fetch_balance adapter with an OpenAI Agent "
                    "(no model run was started)."
                )

    print(
        "\nExample complete — the guarded adapter is ready to use with an OpenAI Agent."
    )


if __name__ == "__main__":
    main()
