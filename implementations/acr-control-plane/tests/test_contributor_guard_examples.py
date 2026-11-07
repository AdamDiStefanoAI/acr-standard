"""Bounded synthetic guard checks; no model, real account, or network call."""

from __future__ import annotations

import builtins
import json
import socket

import httpx
import pytest

from acr.gateway.models import EvaluateResponse
from acr.sdk import ACRClient, ACRDeniedError, ACREscalatedError
from examples import autogen_guard_example as autogen_example
from examples import openai_guard_example as openai_example


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def blocked(*args, **kwargs):
        raise AssertionError("Network is forbidden in these synthetic tests")

    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setenv("OPENAI_AGENTS_DISABLE_TRACING", "1")


def run_example(module):
    if module is openai_example:
        module.main([])
    else:
        module.main()


@pytest.mark.parametrize("module", [openai_example, autogen_example])
def test_mock_example_observes_exact_counts(module, capsys):
    run_example(module)
    output = capsys.readouterr().out
    assert "MOCK gateway" in output
    assert "deletions=0" in output
    assert "balances=1" in output or "lookups=1" in output


@pytest.mark.parametrize("module", [openai_example, autogen_example])
def test_example_fails_if_denied_tool_is_allowed(module, monkeypatch):
    monkeypatch.setattr(module, "guard_tool", lambda tool, **kwargs: tool)
    with pytest.raises(RuntimeError, match="Expected ACR to deny"):
        run_example(module)


@pytest.mark.parametrize("module", [openai_example, autogen_example])
@pytest.mark.parametrize("fault", ["execute_then_deny", "duplicate_allow"])
def test_example_detects_bad_side_effect_counts(module, monkeypatch, fault):
    real_guard = module.guard_tool

    def faulty_guard(tool, **kwargs):
        wrapped = real_guard(tool, **kwargs)

        def invoke(*args, **kw):
            if tool.__name__.startswith("delete") and fault == "execute_then_deny":
                tool(*args, **kw)
                raise ACRDeniedError(EvaluateResponse(decision="deny", reason="too late"))
            result = wrapped(*args, **kw)
            if fault == "duplicate_allow":
                wrapped(*args, **kw)
            return result

        return invoke

    monkeypatch.setattr(module, "guard_tool", faulty_guard)
    with pytest.raises(RuntimeError, match="Unexpected tool side effects"):
        run_example(module)


@pytest.mark.parametrize("use_agents", [False, True], ids=["plain-guard", "real-sdk-dispatch"])
@pytest.mark.parametrize("decision", ["allow", "deny", "modify", "escalate", "timeout"])
def test_decision_payload_and_side_effect_matrix(use_agents, decision):
    if use_agents:
        pytest.importorskip("agents")
    balances: list[str] = []
    deletions: list[str] = []
    requests: list[dict] = []

    def handler(request):
        assert request.url.path == "/acr/evaluate"
        assert request.headers["Authorization"] == "Bearer synthetic-token"
        assert balances == [] and deletions == []
        body = json.loads(request.content)
        assert body["agent_id"] == "synthetic-agent"
        assert body["action"]["parameters"] == {"customer_id": "original"}
        requests.append(body)
        if decision == "timeout":
            raise httpx.ReadTimeout("synthetic timeout", request=request)
        payload = {"decision": decision, "correlation_id": "synthetic-correlation"}
        if decision == "modify":
            payload["modified_action"] = {
                "tool_name": "fetch_balance",
                "parameters": {"customer_id": "approved"},
            }
        if decision == "escalate":
            payload["approval_request_id"] = "synthetic-pending"
        return httpx.Response({"deny": 403, "escalate": 202}.get(decision, 200), json=payload)

    with ACRClient(base_url="http://synthetic", transport=httpx.MockTransport(handler)) as client:
        session = client.create_agent_session("synthetic-agent", "synthetic-token")
        guarded = openai_example.build_guarded_tools(session, balances, deletions)
        agent = openai_example.build_agent(guarded) if use_agents else None

        def invoke():
            if agent is not None:
                return openai_example.invoke_agent_tool(
                    agent, "fetch_balance", {"customer_id": "original"}
                )
            return guarded["fetch_balance"](customer_id="original")

        error = {
            "deny": ACRDeniedError,
            "escalate": ACREscalatedError,
            "timeout": httpx.ReadTimeout,
        }.get(decision)
        if error:
            with pytest.raises(error):
                invoke()
            assert balances == []
        else:
            result = invoke()
            expected = "approved" if decision == "modify" else "original"
            assert balances == [expected]
            assert result == {"customer_id": expected, "balance_usd": 42.5}
        assert deletions == []
        assert len(requests) == 1


def test_sdk_mode_fails_instead_of_skipping_missing_sdk(monkeypatch):
    real_import = builtins.__import__

    def missing(name, *args, **kwargs):
        if name == "agents":
            raise ModuleNotFoundError("synthetic missing SDK")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", missing)
    with pytest.raises(ModuleNotFoundError, match="synthetic missing SDK"):
        openai_example.main(["--agents"])


def test_sdk_mode_fails_instead_of_skipping_broken_registration(monkeypatch):
    agents = pytest.importorskip("agents")

    def broken(*args, **kwargs):
        raise RuntimeError("synthetic broken SDK registration")

    monkeypatch.setattr(agents, "function_tool", broken)
    with pytest.raises(RuntimeError, match="synthetic broken SDK registration"):
        openai_example.main(["--agents"])


def test_gateway_execution_result_prevents_duplicate_local_execution():
    balances: list[str] = []
    deletions: list[str] = []

    def handler(request):
        return httpx.Response(
            200, json={"decision": "allow", "execution_result": {"status": "gateway-executed"}}
        )

    with ACRClient(base_url="http://synthetic", transport=httpx.MockTransport(handler)) as client:
        session = client.create_agent_session("synthetic-agent", "synthetic-token")
        guarded = openai_example.build_guarded_tools(session, balances, deletions)
        assert guarded["fetch_balance"](customer_id="C-100") == {"status": "gateway-executed"}
    assert balances == [] and deletions == []


@pytest.mark.parametrize(
    "url",
    [
        "https://example.com",
        "http://example.com",
        "http://localhost@evil.test",
        "http://localhost/path",
        "http://localhost?key=secret",
    ],
)
def test_live_mode_rejects_nonlocal_or_ambiguous_urls(url):
    with pytest.raises(ValueError, match="disposable gateway"):
        openai_example._local_gateway_url(url)


def test_live_mode_requires_explicit_operator_key(monkeypatch):
    monkeypatch.delenv("ACR_OPERATOR_API_KEY", raising=False)
    monkeypatch.delenv("ACR_BASE_URL", raising=False)
    with pytest.raises(ValueError, match="ACR_OPERATOR_API_KEY is required"):
        openai_example.main(["--live"])


def test_live_mode_does_not_install_mock_transport(monkeypatch):
    monkeypatch.setenv("ACR_OPERATOR_API_KEY", "synthetic-key")
    monkeypatch.setenv("ACR_BASE_URL", "http://localhost:8123")
    observed = {}

    class Client:
        def __init__(self, **kwargs):
            observed.update(kwargs)

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

    monkeypatch.setattr(openai_example, "ACRClient", Client)
    monkeypatch.setattr(
        openai_example, "run_demo", lambda client, **kwargs: observed.update(kwargs)
    )
    openai_example.main(["--live", "--agents"])
    assert observed == {
        "base_url": "http://localhost:8123",
        "operator_api_key": "synthetic-key",
        "use_agents": True,
    }


def test_live_validation_harness_with_synthetic_http():
    """This checks the harness, not a real gateway; CI must still run the live job."""
    pytest.importorskip("agents")
    from scripts.validate_openai_guard_live import validate

    def handler(request):
        if request.url.path == "/acr/agents":
            return openai_example._mock_gateway(request)
        if request.url.path.endswith("/token"):
            return httpx.Response(
                200,
                json={
                    "agent_id": "openai-live-validation",
                    "access_token": "synthetic-token",
                    "expires_in_seconds": 3600,
                },
            )
        action = json.loads(request.content)["action"]
        name = action["tool_name"]
        decision = {
            "query_customer_db": "allow",
            "send_email": "modify",
            "delete_customer": "deny",
            "issue_refund": "escalate",
        }[name]
        payload = {"decision": decision, "correlation_id": f"synthetic-{name}"}
        if decision == "modify":
            payload["modified_action"] = {
                **action,
                "parameters": {**action["parameters"], "to": "[REDACTED]"},
            }
        if decision == "escalate":
            payload["approval_request_id"] = "synthetic-pending"
        return httpx.Response({"deny": 403, "escalate": 202}.get(decision, 200), json=payload)

    with ACRClient(
        base_url="http://synthetic",
        operator_api_key="synthetic-key",
        transport=httpx.MockTransport(handler),
    ) as client:
        observations = validate(client)
    assert [item["decision"] for item in observations] == ["allow", "modify", "deny", "escalate"]
    assert len(observations[-1]["effects_after"]) == 2
