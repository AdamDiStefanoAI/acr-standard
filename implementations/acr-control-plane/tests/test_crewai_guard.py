"""Tests for the CrewAI guard integration (acr.sdk.crewai).

The guard is duck-typed: it works on CrewAI @tool objects and plain
functions, and only needs CrewAI installed to rebuild a real tool object.
The first test class therefore runs with or without CrewAI present; the
second exercises the real CrewAI package when it is installed.
"""

from __future__ import annotations

import importlib.util
from typing import Any, cast

import pytest

from acr.gateway.models import EvaluateResponse
from acr.sdk.client import ACRAgentSession
from acr.sdk.crewai import guard_crewai_tool, guard_crewai_tools
from acr.sdk.errors import ACRDeniedError, ACREscalatedError


class _Session:
    def __init__(self, response: EvaluateResponse) -> None:
        self._response = response
        self.calls: list[dict[str, Any]] = []

    def evaluate_action(self, **kwargs):
        self.calls.append(kwargs)
        return self._response


class _FakeCrewTool:
    """Duck-typed stand-in for a CrewAI @tool object."""

    def __init__(self, func, name: str, description: str) -> None:
        self.func = func
        self.name = name
        self.description = description


def _invoke(tool_like, **kwargs):
    run = getattr(tool_like, "run", None)
    if callable(run) and not isinstance(tool_like, _FakeCrewTool):
        return run(**kwargs)
    func = getattr(tool_like, "func", None)
    if callable(func):
        return func(**kwargs)
    return tool_like(**kwargs)


def _restart(service_name: str) -> str:
    """Restart a named service."""
    return f"restarted {service_name}"


class TestGuardCrewAITool:
    def test_allow_runs_tool_with_same_name(self) -> None:
        session = _Session(EvaluateResponse(decision="allow"))
        fake = _FakeCrewTool(_restart, "restart_service", "Restart a named service.")
        guarded = guard_crewai_tool(fake, session=cast(ACRAgentSession, session))
        assert _invoke(guarded, service_name="api") == "restarted api"
        assert session.calls[0]["tool_name"] == "restart_service"
        assert session.calls[0]["parameters"] == {"service_name": "api"}

    def test_deny_raises_before_tool_executes(self) -> None:
        executed: list[str] = []

        def impl(service_name: str) -> str:
            executed.append(service_name)
            return "should not happen"

        session = _Session(EvaluateResponse(decision="deny", reason="not tonight"))
        fake = _FakeCrewTool(impl, "restart_service", "Restart a named service.")
        guarded = guard_crewai_tool(fake, session=cast(ACRAgentSession, session))
        with pytest.raises(ACRDeniedError, match="not tonight"):
            _invoke(guarded, service_name="api")
        assert executed == []

    def test_escalate_raises(self) -> None:
        session = _Session(EvaluateResponse(decision="escalate", reason="needs a human"))
        fake = _FakeCrewTool(_restart, "restart_service", "Restart a named service.")
        guarded = guard_crewai_tool(fake, session=cast(ACRAgentSession, session))
        with pytest.raises(ACREscalatedError):
            _invoke(guarded, service_name="api")

    def test_plain_function_accepted(self) -> None:
        session = _Session(EvaluateResponse(decision="allow"))
        guarded = guard_crewai_tool(_restart, session=cast(ACRAgentSession, session))
        assert _invoke(guarded, service_name="db") == "restarted db"
        assert session.calls[0]["tool_name"] == "_restart"

    def test_basetool_like_object_rejected_with_guidance(self) -> None:
        class _BaseToolLike:
            name = "class_tool"

            def _run(self, x: int) -> int:
                return x

        session = _Session(EvaluateResponse(decision="allow"))
        with pytest.raises(TypeError, match="BaseTool"):
            guard_crewai_tool(_BaseToolLike(), session=cast(ACRAgentSession, session))

    def test_guard_list(self) -> None:
        session = _Session(EvaluateResponse(decision="allow"))
        fakes = [
            _FakeCrewTool(_restart, "restart_service", "Restart a named service."),
            _FakeCrewTool(_restart, "restart_db", "Restart a named service."),
        ]
        guarded = guard_crewai_tools(fakes, session=cast(ACRAgentSession, session))
        assert len(guarded) == 2
        assert _invoke(guarded[1], service_name="db") == "restarted db"
        assert session.calls[0]["tool_name"] == "restart_db"


_CREWAI_AVAILABLE = importlib.util.find_spec("crewai") is not None


@pytest.mark.skipif(not _CREWAI_AVAILABLE, reason="crewai not installed")
class TestGuardCrewAIToolRealPackage:
    def test_real_tool_round_trip(self) -> None:
        from crewai.tools import tool as crewai_tool

        @crewai_tool("restart_service")
        def restart_service(service_name: str) -> str:
            """Restart a named service."""
            return f"restarted {service_name}"

        session = _Session(EvaluateResponse(decision="allow"))
        guarded = guard_crewai_tool(restart_service, session=cast(ACRAgentSession, session))
        assert guarded.name == "restart_service"
        assert guarded.run(service_name="api") == "restarted api"
        assert session.calls[0]["tool_name"] == "restart_service"

    def test_real_tool_deny(self) -> None:
        from crewai.tools import tool as crewai_tool

        @crewai_tool("restart_service")
        def restart_service(service_name: str) -> str:
            """Restart a named service."""
            return f"restarted {service_name}"

        session = _Session(EvaluateResponse(decision="deny", reason="blocked by policy"))
        guarded = guard_crewai_tool(restart_service, session=cast(ACRAgentSession, session))
        with pytest.raises(ACRDeniedError, match="blocked by policy"):
            guarded.run(service_name="api")
