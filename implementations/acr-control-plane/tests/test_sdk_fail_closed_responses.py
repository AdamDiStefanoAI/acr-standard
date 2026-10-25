"""Malformed synthetic gateway responses must not reach local tool bodies."""

from __future__ import annotations

import inspect
import json
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from acr.gateway.models import EvaluateResponse
from acr.pillar2_policy.models import PolicyDecision, PolicyEvaluationResult
from acr.sdk import (
    ACRClient,
    ACRDeniedError,
    ACREscalatedError,
    ACRHTTPError,
    ACRSDKError,
    AsyncACRClient,
    guard_async_tool,
    guard_tool,
)


async def exercise(async_mode, status, payload, calls, *, execute_locally=True):
    def tool(amount: int = 999):
        calls.append(amount)
        return amount

    def handler(request):
        assert calls == [], "Authorization must precede the local side effect"
        assert json.loads(request.content)["action"] == {
            "tool_name": "refund",
            "parameters": {"amount": 999},
        }
        return httpx.Response(status, json=payload)

    client_type = AsyncACRClient if async_mode else ACRClient
    client = client_type(
        base_url="https://synthetic.invalid", transport=httpx.MockTransport(handler)
    )
    try:
        session = client.create_agent_session("synthetic-agent", "synthetic-token")
        guard = guard_async_tool if async_mode else guard_tool
        wrapped = guard(
            tool, session=session, tool_name="refund", execute_locally_on_allow=execute_locally
        )
        result = wrapped()
        return await result if inspect.isawaitable(result) else result
    finally:
        if async_mode:
            await client.aclose()
        else:
            client.close()


@pytest.mark.parametrize("async_mode", [False, True], ids=["sync", "async"])
@pytest.mark.parametrize("status", [202, 403, 500, 503])
@pytest.mark.parametrize("decision", ["allow", "modify"])
async def test_non_success_status_cannot_authorize_local_effect(async_mode, status, decision):
    calls = []
    payload = {"decision": decision}
    if decision == "modify":
        payload["modified_action"] = {"tool_name": "refund", "parameters": {"amount": 25}}
    with pytest.raises(ACRHTTPError, match="cannot authorize execution"):
        await exercise(async_mode, status, payload, calls)
    assert calls == []


@pytest.mark.parametrize("async_mode", [False, True], ids=["sync", "async"])
@pytest.mark.parametrize("execute_locally", [False, True])
@pytest.mark.parametrize(
    "action,message",
    [
        (None, "explicit modified action"),
        ({"tool_name": "other", "parameters": {"amount": 25}}, "requested tool"),
        ({"tool_name": "refund"}, "explicit parameters"),
    ],
)
async def test_incomplete_or_mismatched_modify_cannot_execute(
    async_mode, execute_locally, action, message
):
    calls = []
    payload = {"decision": "modify", "execution_result": {"synthetic": True}}
    if action is not None:
        payload["modified_action"] = action
    with pytest.raises(ACRSDKError, match=message):
        await exercise(async_mode, 200, payload, calls, execute_locally=execute_locally)
    assert calls == []


@pytest.mark.parametrize("async_mode", [False, True], ids=["sync", "async"])
@pytest.mark.parametrize(
    "status,payload,expected,error",
    [
        (200, {"decision": "allow"}, [999], None),
        (200, {"decision": "deny"}, [], ACRDeniedError),
        (403, {"decision": "deny"}, [], ACRDeniedError),
        (500, {"decision": "deny"}, [], ACRDeniedError),
        (503, {"decision": "deny"}, [], ACRDeniedError),
        (200, {"decision": "escalate"}, [], ACREscalatedError),
        (202, {"decision": "escalate"}, [], ACREscalatedError),
        (
            200,
            {
                "decision": "modify",
                "modified_action": {"tool_name": "refund", "parameters": {"amount": 25}},
            },
            [25],
            None,
        ),
        (
            200,
            {
                "decision": "modify",
                "modified_action": {"tool_name": "refund", "parameters": {"amount": 999}},
            },
            [999],
            None,
        ),
    ],
)
async def test_valid_decisions_preserve_exact_local_effects(
    async_mode, status, payload, expected, error
):
    calls = []
    if error:
        with pytest.raises(error):
            await exercise(async_mode, status, payload, calls)
    else:
        result = await exercise(async_mode, status, payload, calls)
        assert result == expected[0]
    assert calls == expected


@pytest.mark.parametrize("async_mode", [False, True], ids=["sync", "async"])
async def test_explicit_empty_modified_payload_and_guard_alias_remain_valid(async_mode):
    calls = []
    result = await exercise(
        async_mode,
        200,
        {"decision": "modify", "modified_action": {"tool_name": "refund", "parameters": {}}},
        calls,
    )
    assert calls == [999]
    assert result == 999


@pytest.mark.parametrize("async_mode", [False, True], ids=["sync", "async"])
@pytest.mark.parametrize(
    "payload",
    [
        {"decision": "modify"},
        {"decision": "modify", "modified_action": None},
        {"decision": "modify", "modified_action": {"tool_name": "refund"}},
        {
            "decision": "modify",
            "modified_action": {"tool_name": "other", "parameters": {"amount": 25}},
        },
    ],
)
async def test_raw_client_rejects_incomplete_or_mismatched_transformation(async_mode, payload):
    client_type = AsyncACRClient if async_mode else ACRClient
    client = client_type(
        base_url="https://synthetic.invalid",
        transport=httpx.MockTransport(lambda request: httpx.Response(200, json=payload)),
    )
    try:
        with pytest.raises(ACRHTTPError):
            result = client.evaluate_action(
                agent_id="synthetic-agent",
                access_token="synthetic-token",
                tool_name="refund",
                parameters={"amount": 999},
            )
            if inspect.isawaitable(result):
                await result
    finally:
        if async_mode:
            await client.aclose()
        else:
            client.close()


@pytest.mark.parametrize("async_mode", [False, True], ids=["sync", "async"])
@pytest.mark.parametrize(
    "action",
    [None, {"tool_name": "tool"}, {"tool_name": "other", "parameters": {"amount": 25}}],
)
async def test_custom_session_cannot_bypass_guard_transformation_checks(async_mode, action):
    calls = []
    response = EvaluateResponse.model_validate({"decision": "modify", "modified_action": action})

    class SyncSession:
        def evaluate_action(self, **kwargs):
            return response

    class AsyncSession:
        async def evaluate_action(self, **kwargs):
            return response

    def tool(amount=999):
        calls.append(amount)

    guard = guard_async_tool if async_mode else guard_tool
    wrapped = guard(tool, session=AsyncSession() if async_mode else SyncSession())
    with pytest.raises(ACRSDKError):
        result = wrapped()
        if inspect.isawaitable(result):
            await result
    assert calls == []


@pytest.mark.parametrize(
    "policy_action,expected",
    [
        ({"description": "Reviewed by policy"}, "C-001"),
        ({"parameters": {"customer_id": "C-002"}}, "C-002"),
    ],
)
async def test_sdk_accepts_actual_gateway_modify_response(
    async_client, sample_agent, policy_action, expected
):
    """Real router/SDK, isolated SQLite and mocked policy/Redis/auth fixtures."""
    policy = PolicyEvaluationResult(
        final_decision="modify",
        decisions=[PolicyDecision(policy_id="synthetic-policy", decision="modify")],
        modified_action=policy_action,
    )
    calls = []

    async def query_customer_db(customer_id):
        calls.append(customer_id)
        return customer_id

    sdk = AsyncACRClient(base_url="http://test", client=async_client)
    session = sdk.create_agent_session(sample_agent.agent_id, "synthetic-token")
    guarded = guard_async_tool(query_customer_db, session=session)
    with (
        patch("acr.gateway.router.evaluate_policy", new_callable=AsyncMock, return_value=policy),
        patch("acr.gateway.router._persist_policy_decisions", new_callable=AsyncMock),
    ):
        assert await guarded(customer_id="C-001") == expected
    assert calls == [expected]
