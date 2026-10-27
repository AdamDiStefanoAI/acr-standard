"""Mock-backed guard pattern for Microsoft AutoGen function tools.

From the repository root (Python 3.11 or 3.12):

    python -m pip install -e implementations/acr-control-plane
    python implementations/acr-control-plane/examples/autogen_guard_example.py

No AutoGen tool dispatch, real gateway, model, or external service is used.
The version-specific framework registration is intentionally left as guidance.
"""

from __future__ import annotations

import importlib.util
import json
from datetime import UTC, datetime
from typing import Any

import httpx

from acr.pillar1_identity.models import AgentRegisterRequest
from acr.sdk import ACRClient, ACRDeniedError, guard_tool


def _mock_gateway(request: httpx.Request) -> httpx.Response:
    """Mock agent registration, token issuance, and allow/deny decisions."""
    if request.url.path == "/acr/agents":
        registration = json.loads(request.content)
        now = datetime.now(UTC).isoformat()
        return httpx.Response(
            200,
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
    if request.url.path == "/acr/agents/autogen-guard-demo/token":
        return httpx.Response(
            200,
            json={
                "agent_id": "autogen-guard-demo",
                "access_token": "demo-token",
                "token_type": "bearer",
                "expires_in_seconds": 3600,
            },
        )

    body = json.loads(request.content)
    tool_name = body.get("action", {}).get("tool_name", "")
    if tool_name == "delete_record":
        return httpx.Response(
            200,
            json={
                "decision": "deny",
                "reason": "delete_record is forbidden for this demo agent",
                "error_code": "TOOL_FORBIDDEN",
                "correlation_id": "demo-corr-deny",
            },
        )
    return httpx.Response(
        200,
        json={
            "decision": "allow",
            "reason": f"{tool_name} is allowed for this demo agent",
            "correlation_id": "demo-corr-allow",
            "latency_ms": 5,
        },
    )


def main() -> None:
    print("MOCK gateway; AutoGen registration is guidance only, not exercised.")
    # A mock transport keeps the example local: no Docker or gateway is needed.
    with ACRClient(
        base_url="http://gateway.local",
        operator_api_key="demo-key",
        transport=httpx.MockTransport(_mock_gateway),
    ) as client:
        client.ensure_agent_registered(
            AgentRegisterRequest(
                agent_id="autogen-guard-demo",
                owner="example@example.com",
                purpose="Demonstrate ACR-guarded AutoGen function tools",
                allowed_tools=["lookup_record"],
                forbidden_tools=["delete_record"],
            )
        )
        session = client.issue_agent_session("autogen-guard-demo")

        lookups: list[str] = []
        deletions: list[str] = []

        # Local implementations are only called after ACR allows the action.
        def lookup_record(record_id: str) -> dict[str, Any]:
            """Look up a demo record without accessing an external service."""
            lookups.append(record_id)
            return {"record_id": record_id, "status": "found"}

        def delete_record(record_id: str) -> str:
            """Demo destructive action; ACR policy denies it before execution."""
            deletions.append(record_id)
            return f"deleted {record_id}"

        guarded_lookup_record = guard_tool(
            lookup_record, session=session, tool_name="lookup_record"
        )
        guarded_delete_record = guard_tool(
            delete_record, session=session, tool_name="delete_record"
        )

        print("Allowed tool result:")
        print(guarded_lookup_record(record_id="record-123"))

        print("\nDenied tool result:")
        try:
            guarded_delete_record(record_id="record-123")
        except ACRDeniedError as exc:
            print(f"ACRDeniedError: {exc}")
        else:
            raise RuntimeError("Expected ACR to deny delete_record")
        if lookups != ["record-123"] or deletions:
            raise RuntimeError("Unexpected tool side effects")
        print(f"Side effects: lookups={len(lookups)}, deletions={len(deletions)}")

        # AutoGen registration is intentionally an adapter step. Microsoft
        # AutoGen has multiple package/API generations (for example, legacy
        # pyautogen and newer autogen-core); register this guarded callable as
        # a function tool using the API supported by your installed version.
        # For instance, your agent's tool list should expose a wrapper that
        # delegates to guarded_lookup_record, never the unguarded implementation.
        autogen_available = (
            importlib.util.find_spec("autogen_core") is not None
            or importlib.util.find_spec("autogen") is not None
        )
        if not autogen_available:
            print(
                "\nAutoGen SDK is not installed; skipping framework registration. "
                "Register a function-tool adapter that calls "
                "`guarded_lookup_record` with your AutoGen version's API."
            )
        else:
            print(
                "\nAutoGen package detected. Registration is left as a version-specific "
                "adapter; expose `guarded_lookup_record` as your function tool."
            )


if __name__ == "__main__":
    main()
