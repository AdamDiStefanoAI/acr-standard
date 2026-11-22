"""CrewAI tool guards built on top of the ACR SDK.

CrewAI tools created with the ``@tool`` decorator are thin wrappers around a
plain function. These helpers guard that function with ACR and hand CrewAI
back a tool with the same name and description, so adoption is a one-line
change per tool instead of a hand-written wrapper function per tool (the
pattern the original example had to use):

    from crewai.tools import tool
    from acr.sdk.crewai import guard_crewai_tool

    @tool("restart_service")
    def restart_service(service_name: str) -> str:
        ...

    agent = Agent(tools=[guard_crewai_tool(restart_service, session=session)])

On an ``allow`` decision the tool runs with the (possibly gateway-modified)
parameters; on ``deny`` an :class:`ACRDeniedError` is raised before the tool
body executes, and on ``escalate`` an :class:`ACREscalatedError` is raised so
the crew cannot proceed as if the action were approved.

Scope: function-style tools (``@tool``) and plain functions. Class-based
``BaseTool`` subclasses define their behavior in ``_run`` and are not
rewrappable without losing their schema; guard the function the tool calls,
or call ``guard_tool`` on the underlying callable before constructing them.
"""

from __future__ import annotations

import inspect
from collections.abc import Callable
from typing import Any

from acr.gateway.models import IntentRequest
from acr.sdk.client import ACRAgentSession
from acr.sdk.langgraph import guard_tool


def _extract_callable(tool_obj: Any) -> Callable[..., Any]:
    """Return the plain function behind a CrewAI tool object."""
    func = getattr(tool_obj, "func", None)
    if callable(func):
        return func
    if callable(tool_obj):
        return tool_obj
    raise TypeError(
        "guard_crewai_tool expects a CrewAI @tool object or a plain callable; "
        "class-based BaseTool subclasses are not supported — guard the "
        "function the tool calls instead."
    )


def guard_crewai_tool(
    tool_obj: Any,
    *,
    session: ACRAgentSession,
    tool_name: str | None = None,
    description: str | None = None,
    context_builder: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
    intent_builder: Callable[[dict[str, Any]], IntentRequest | dict[str, Any] | None] | None = None,
    execute_locally_on_allow: bool = True,
) -> Any:
    """Guard one CrewAI tool with ACR runtime enforcement.

    Accepts a tool created by CrewAI's ``@tool`` decorator (or a plain
    function) and returns a CrewAI tool with the same name and description
    whose every invocation is authorized by ACR first. When CrewAI is not
    installed, returns the guarded plain function instead, which keeps the
    guard usable (and testable) outside a CrewAI deployment.
    """
    func = _extract_callable(tool_obj)
    resolved_name = tool_name or getattr(tool_obj, "name", None) or func.__name__
    resolved_description = (
        description
        or getattr(tool_obj, "description", None)
        or inspect.getdoc(func)
        or f"Guarded ACR tool: {resolved_name}"
    )
    guarded = guard_tool(
        func,
        session=session,
        tool_name=resolved_name,
        description=resolved_description,
        context_builder=context_builder,
        intent_builder=intent_builder,
        execute_locally_on_allow=execute_locally_on_allow,
    )
    # CrewAI derives a tool's description from the function docstring and
    # refuses functions without one. The guarded wrapper inherits the
    # original docstring, which may be empty even when the tool object
    # carried a description; stamp the resolved description on in that case.
    if not inspect.getdoc(guarded):
        guarded.__doc__ = resolved_description
    try:
        from crewai.tools import tool as crewai_tool
    except ImportError:
        return guarded
    return crewai_tool(resolved_name)(guarded)


def guard_crewai_tools(
    tools: list[Any],
    *,
    session: ACRAgentSession,
    context_builder: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
    intent_builder: Callable[[dict[str, Any]], IntentRequest | dict[str, Any] | None] | None = None,
    execute_locally_on_allow: bool = True,
) -> list[Any]:
    """Guard a list of CrewAI tools with the same session (agent toolkits)."""
    return [
        guard_crewai_tool(
            tool_obj,
            session=session,
            context_builder=context_builder,
            intent_builder=intent_builder,
            execute_locally_on_allow=execute_locally_on_allow,
        )
        for tool_obj in tools
    ]
