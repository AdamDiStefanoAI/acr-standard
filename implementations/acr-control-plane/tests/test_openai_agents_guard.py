"""Tests for the OpenAI Agents SDK guard integration (acr.sdk.openai_agents).

The guard is duck-typed: it works on plain functions (the form the SDK's
``function_tool`` consumes) and only needs the Agents SDK installed to
build a real ``FunctionTool``. The first test class therefore runs with
or without the SDK present; the second exercises the real package when
it is installed, invoking tools through the SDK's own dispatch
(``FunctionTool.on_invoke_tool``) with no model run.
"""

from __future__ import annotations

import asyncio
import importlib.util
import json
from typing import Any, cast

import pytest

from acr.gateway.models import ActionRequest, EvaluateResponse
from acr.sdk.client import ACRAgentSession
from acr.sdk.errors import ACRDeniedError, ACREscalatedError
from acr.sdk.openai_agents import guard_openai_tool, guard_openai_tools


class _Session:
    def __init__(self, response: EvaluateResponse) -> None:
        self._response = response
        self.calls: list[dict[str, Any]] = []

    def evaluate_action(self, **kwargs):
        self.calls.append(kwargs)
        return self._response


class _FakeAgentsTool:
    """Duck-typed stand-in exposing the wrapped function as .func."""

    def __init__(self, func, name: str, description: str) -> None:
        self.func = func
        self.name = name
        self.description = description


def _invoke(tool_like, **kwargs):
    """Invoke a guarded result: a FunctionTool via SDK dispatch, else directly."""
    on_invoke = getattr(tool_like, "on_invoke_tool", None)
    if callable(on_invoke):
        from agents.tool_context import ToolContext

        arguments = json.dumps(kwargs)
        context = ToolContext(
            context=None,
            tool_name=tool_like.name,
            tool_call_id="test-call",
            tool_arguments=arguments,
        )
        return asyncio.run(on_invoke(context, arguments))
    func = getattr(tool_like, "func", None)
    if callable(func):
        return func(**kwargs)
    return tool_like(**kwargs)


def _restart(service_name: str) -> str:
    """Restart a named service."""
    return f"restarted {service_name}"


class TestGuardOpenAITool:
    def test_allow_runs_tool_with_same_name(self) -> None:
        session = _Session(EvaluateResponse(decision="allow"))
        fake = _FakeAgentsTool(_restart, "restart_service", "Restart a named service.")
        guarded = guard_openai_tool(fake, session=cast(ACRAgentSession, session))
        assert _invoke(guarded, service_name="api") == "restarted api"
        assert session.calls[0]["tool_name"] == "restart_service"
        assert session.calls[0]["parameters"] == {"service_name": "api"}

    def test_deny_raises_before_tool_executes(self) -> None:
        executed: list[str] = []

        def impl(service_name: str) -> str:
            executed.append(service_name)
            return "should not happen"

        session = _Session(EvaluateResponse(decision="deny", reason="not tonight"))
        fake = _FakeAgentsTool(impl, "restart_service", "Restart a named service.")
        guarded = guard_openai_tool(fake, session=cast(ACRAgentSession, session))
        with pytest.raises(ACRDeniedError, match="not tonight"):
            _invoke(guarded, service_name="api")
        assert executed == []

    def test_deny_error_carries_decision_receipt(self) -> None:
        """The raised error binds the call to its durable decision record."""
        session = _Session(
            EvaluateResponse(decision="deny", reason="blocked", correlation_id="corr-123")
        )
        guarded = guard_openai_tool(_restart, session=cast(ACRAgentSession, session))
        with pytest.raises(ACRDeniedError) as excinfo:
            _invoke(guarded, service_name="api")
        assert excinfo.value.response.correlation_id == "corr-123"

    def test_escalate_raises_with_approval_binding(self) -> None:
        session = _Session(
            EvaluateResponse(
                decision="escalate",
                reason="needs a human",
                approval_request_id="appr-9",
            )
        )
        fake = _FakeAgentsTool(_restart, "restart_service", "Restart a named service.")
        guarded = guard_openai_tool(fake, session=cast(ACRAgentSession, session))
        with pytest.raises(ACREscalatedError) as excinfo:
            _invoke(guarded, service_name="api")
        assert excinfo.value.response.approval_request_id == "appr-9"

    def test_modify_applies_modified_parameters(self) -> None:
        session = _Session(
            EvaluateResponse(
                decision="modify",
                modified_action=ActionRequest(
                    tool_name="restart_service",
                    parameters={"service_name": "approved-target"},
                ),
            )
        )
        fake = _FakeAgentsTool(_restart, "restart_service", "Restart a named service.")
        guarded = guard_openai_tool(fake, session=cast(ACRAgentSession, session))
        assert _invoke(guarded, service_name="api") == "restarted approved-target"

    def test_plain_function_accepted(self) -> None:
        session = _Session(EvaluateResponse(decision="allow"))
        guarded = guard_openai_tool(_restart, session=cast(ACRAgentSession, session))
        assert _invoke(guarded, service_name="db") == "restarted db"
        assert session.calls[0]["tool_name"] == "_restart"

    def test_functiontool_like_object_rejected_with_guidance(self) -> None:
        class _FunctionToolLike:
            name = "already_wrapped"

            async def on_invoke_tool(self, ctx, arguments):  # pragma: no cover
                return None

        session = _Session(EvaluateResponse(decision="allow"))
        with pytest.raises(TypeError, match="FunctionTool"):
            guard_openai_tool(_FunctionToolLike(), session=cast(ACRAgentSession, session))

    def test_guard_list(self) -> None:
        session = _Session(EvaluateResponse(decision="allow"))
        fakes = [
            _FakeAgentsTool(_restart, "restart_service", "Restart a named service."),
            _FakeAgentsTool(_restart, "restart_db", "Restart a named service."),
        ]
        guarded = guard_openai_tools(fakes, session=cast(ACRAgentSession, session))
        assert len(guarded) == 2
        assert _invoke(guarded[1], service_name="db") == "restarted db"
        assert session.calls[0]["tool_name"] == "restart_db"


_AGENTS_AVAILABLE = importlib.util.find_spec("agents") is not None


@pytest.mark.skipif(not _AGENTS_AVAILABLE, reason="openai-agents not installed")
class TestGuardOpenAIToolRealPackage:
    def test_real_function_tool_round_trip(self) -> None:
        session = _Session(EvaluateResponse(decision="allow"))
        guarded = guard_openai_tool(_restart, session=cast(ACRAgentSession, session))
        assert guarded.name == "_restart"
        assert _invoke(guarded, service_name="api") == "restarted api"
        assert session.calls[0]["tool_name"] == "_restart"

    def test_real_function_tool_uses_tool_object_name(self) -> None:
        fake = _FakeAgentsTool(_restart, "restart_service", "Restart a named service.")
        session = _Session(EvaluateResponse(decision="allow"))
        guarded = guard_openai_tool(fake, session=cast(ACRAgentSession, session))
        assert guarded.name == "restart_service"
        assert guarded.description == "Restart a named service."
        assert _invoke(guarded, service_name="api") == "restarted api"

    def test_real_function_tool_deny_propagates_not_converted(self) -> None:
        """failure_error_function=None: denial raises instead of becoming text."""
        session = _Session(EvaluateResponse(decision="deny", reason="blocked by policy"))
        guarded = guard_openai_tool(_restart, session=cast(ACRAgentSession, session))
        with pytest.raises(ACRDeniedError, match="blocked by policy"):
            _invoke(guarded, service_name="api")

    def test_real_agent_registration(self) -> None:
        from agents import Agent

        session = _Session(EvaluateResponse(decision="allow"))
        guarded = guard_openai_tools([_restart], session=cast(ACRAgentSession, session))
        agent = Agent(name="ops", instructions="ops agent", tools=guarded)
        assert [t.name for t in agent.tools] == ["_restart"]
