"""OpenAI Agents SDK tools guarded by ACR, without a model or paid API call.

From the repository root (Python 3.11 or 3.12):

    python -m pip install -e implementations/acr-control-plane
    python implementations/acr-control-plane/examples/openai_guard_example.py

This default is an explicitly mocked ACR demonstration. For real SDK tool
dispatch and the disposable local quickstart gateway, see openai_guard_example.md.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

import httpx

from acr.pillar1_identity.models import AgentRegisterRequest
from acr.sdk import ACRAgentSession, ACRClient, ACRDeniedError, guard_tool

AGENT_ID = "openai-guard-demo"


def _mock_gateway(request: httpx.Request) -> httpx.Response:
    """Synthetic onboarding and allow/deny; never contacts a gateway."""
    if request.method == "POST" and request.url.path == "/acr/agents":
        registration = json.loads(request.content)
        now = datetime.now(UTC).isoformat()
        return httpx.Response(
            201,
            json={
                **registration,
                "is_active": True,
                "parent_agent_id": None,
                "health_status": "unknown",
                "last_heartbeat_at": None,
                "created_at": now,
                "updated_at": now,
            },
        )
    if request.method == "POST" and request.url.path == f"/acr/agents/{AGENT_ID}/token":
        return httpx.Response(
            200,
            json={
                "agent_id": AGENT_ID,
                "access_token": "synthetic-demo-token",
                "token_type": "bearer",
                "expires_in_seconds": 3600,
            },
        )
    if request.method != "POST" or request.url.path != "/acr/evaluate":
        raise AssertionError(f"Unexpected demo request: {request.method} {request.url.path}")
    tool_name = json.loads(request.content).get("action", {}).get("tool_name", "")
    allowed = tool_name == "fetch_balance"
    return httpx.Response(
        200 if allowed else 403,
        json={
            "decision": "allow" if allowed else "deny",
            "reason": f"{tool_name} is {'allowed' if allowed else 'forbidden'} for this demo agent",
            "correlation_id": "synthetic-demo-allow" if allowed else "synthetic-demo-deny",
        },
    )


def build_guarded_tools(
    session: ACRAgentSession, balances: list[str], deletions: list[str]
) -> dict[str, Any]:
    """Only in-memory list mutations stand in for actual business side effects."""

    def fetch_balance(customer_id: str) -> dict[str, Any]:
        """Return a fake customer balance and record its execution."""
        balances.append(customer_id)
        return {"customer_id": customer_id, "balance_usd": 42.5}

    def delete_account(customer_id: str) -> dict[str, Any]:
        """Record a synthetic deletion; never touches any account."""
        deletions.append(customer_id)
        return {"status": "deleted", "customer_id": customer_id}

    return {
        "fetch_balance": guard_tool(
            fetch_balance,
            session=session,
            tool_name="fetch_balance",
            execute_locally_on_allow=False,
        ),
        "delete_account": guard_tool(
            delete_account,
            session=session,
            tool_name="delete_account",
            execute_locally_on_allow=False,
        ),
    }


def build_agent(guarded_tools: dict[str, Any]):
    """Register only guarded callables; do not start an agent/model run."""
    from agents import Agent, function_tool

    # Propagate DENY/ESCALATE instead of converting control exceptions into
    # ordinary tool-result text. Each registered callable still asks ACR first.
    return Agent(
        name="ACR guarded example",
        instructions="Use the guarded tools for synthetic customer records.",
        tools=[function_tool(tool, failure_error_function=None) for tool in guarded_tools.values()],
    )


def invoke_agent_tool(agent, tool_name: str, parameters: dict[str, Any]) -> Any:
    """Exercise real SDK FunctionTool dispatch deterministically, without an LLM."""
    from agents.tool_context import ToolContext

    tool = next(tool for tool in agent.tools if tool.name == tool_name)
    arguments = json.dumps(parameters)
    context = ToolContext(
        context=None,
        tool_name=tool_name,
        tool_call_id="synthetic-demo-call",
        tool_arguments=arguments,
    )
    return asyncio.run(tool.on_invoke_tool(context, arguments))


def run_demo(client: ACRClient, *, use_agents: bool = False) -> None:
    registration = client.ensure_agent_registered(
        AgentRegisterRequest(
            agent_id=AGENT_ID,
            owner="example@example.com",
            purpose="Demonstrate ACR-guarded OpenAI Agents SDK tools",
            allowed_tools=["fetch_balance"],
            forbidden_tools=["delete_account"],
        )
    )
    if registration.allowed_tools != ["fetch_balance"] or registration.forbidden_tools != [
        "delete_account"
    ]:
        raise RuntimeError(
            "Existing demo agent has different tool rules; use a fresh disposable stack"
        )
    session = client.issue_agent_session(AGENT_ID)
    balances: list[str] = []
    deletions: list[str] = []
    guarded = build_guarded_tools(session, balances, deletions)
    agent = build_agent(guarded) if use_agents else None

    def invoke(name: str) -> Any:
        if agent is not None:
            return invoke_agent_tool(agent, name, {"customer_id": "C-100"})
        return guarded[name](customer_id="C-100")

    print("Allowed tool result:")
    print(invoke("fetch_balance"))
    print("\nDenied tool result:")
    try:
        invoke("delete_account")
    except ACRDeniedError as exc:
        print(f"DENIED before execution: {exc}")
    else:
        raise RuntimeError("Expected ACR to deny delete_account")
    if balances != ["C-100"] or deletions:
        raise RuntimeError("Unexpected tool side effects")
    print(f"Side effects: balances={len(balances)}, deletions={len(deletions)}")
    print(
        "Real SDK tool dispatch; no model run."
        if use_agents
        else "Plain guarded call; SDK not used."
    )


def _local_gateway_url(value: str) -> str:
    parsed = urlsplit(value)
    if (
        parsed.scheme != "http"
        or parsed.hostname not in {"localhost", "127.0.0.1", "::1"}
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("Use an http://localhost, 127.0.0.1, or [::1] disposable gateway URL")
    return value.rstrip("/")


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--live", action="store_true", help="Use the disposable local ACR gateway")
    parser.add_argument(
        "--agents", action="store_true", help="Use real OpenAI Agents SDK tool dispatch"
    )
    args = parser.parse_args(argv)
    if args.live:
        base_url = _local_gateway_url(os.getenv("ACR_BASE_URL", "http://localhost:8000"))
        key = os.environ.get("ACR_OPERATOR_API_KEY")
        if not key:
            raise ValueError(
                "ACR_OPERATOR_API_KEY is required for --live; see openai_guard_example.md"
            )
        print("LIVE disposable local gateway; local in-memory tools only.")
        with ACRClient(base_url=base_url, operator_api_key=key) as client:
            run_demo(client, use_agents=args.agents)
    else:
        print("MOCK gateway: no real ACR policy evaluation or audit persistence.")
        with ACRClient(
            base_url="http://gateway.local",
            operator_api_key="synthetic-demo-key",
            transport=httpx.MockTransport(_mock_gateway),
        ) as client:
            run_demo(client, use_agents=args.agents)


if __name__ == "__main__":
    main()
