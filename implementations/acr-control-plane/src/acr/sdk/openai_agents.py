"""OpenAI Agents SDK tool guards built on top of the ACR SDK.

The Agents SDK dispatches tools through ``FunctionTool`` objects created
with the ``@function_tool`` decorator (or ``function_tool(fn)``) from a
plain function. These helpers guard that function with ACR and hand the
SDK back a ``FunctionTool`` with the same name and description, so
adoption is a one-line change per tool:

    from agents import Agent
    from acr.sdk.openai_agents import guard_openai_tool

    def restart_service(service_name: str) -> str:
        ...

    agent = Agent(
        name="ops",
        tools=[guard_openai_tool(restart_service, session=session)],
    )

On an ``allow`` decision the tool runs with the (possibly
gateway-modified) parameters; on ``deny`` an :class:`ACRDeniedError` is
raised before the tool body executes, and on ``escalate`` an
:class:`ACREscalatedError` is raised so the agent cannot proceed as if
the action were approved. Both errors carry the full
:class:`~acr.gateway.models.EvaluateResponse` — including the
``correlation_id`` of the durable decision record and, for escalations,
the ``approval_request_id`` — which is how the guard binds the tool call
to its evidence receipt: anything the caller logs or surfaces from the
error traces back to the recorded decision.

The guarded ``FunctionTool`` is built with ``failure_error_function=None``
so ACR denials and escalations propagate to the caller instead of being
converted into ordinary tool-result text the model could read as a
successful (or merely failed) execution.

Scope: plain functions and duck-typed tool objects exposing the wrapped
function as ``.func``. An already-built ``FunctionTool`` does not expose
its wrapped function, so it cannot be re-wrapped without losing the
guard's parameter binding — guard the function first, then let this
adapter build the ``FunctionTool``. When the Agents SDK is not
installed, the adapter returns the guarded plain function instead,
which keeps the guard usable (and testable) outside an Agents
deployment; pass that function to ``function_tool`` yourself once the
SDK is available.
"""

from __future__ import annotations

import inspect
from collections.abc import Callable
from typing import Any

from acr.gateway.models import IntentRequest
from acr.sdk.client import ACRAgentSession
from acr.sdk.langgraph import guard_tool


def _extract_callable(tool_obj: Any) -> Callable[..., Any]:
    """Return the plain function behind an Agents-style tool object."""
    func = getattr(tool_obj, "func", None)
    if callable(func):
        return func
    if callable(tool_obj):
        return tool_obj
    raise TypeError(
        "guard_openai_tool expects a plain callable or an object exposing "
        "the wrapped function as .func; an already-built FunctionTool does "
        "not expose its function — guard the function before wrapping it "
        "with function_tool."
    )


def guard_openai_tool(
    tool_obj: Any,
    *,
    session: ACRAgentSession,
    tool_name: str | None = None,
    description: str | None = None,
    context_builder: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
    intent_builder: Callable[[dict[str, Any]], IntentRequest | dict[str, Any] | None] | None = None,
    execute_locally_on_allow: bool = True,
) -> Any:
    """Guard one OpenAI Agents SDK tool with ACR runtime enforcement.

    Accepts a plain function (the form ``function_tool`` consumes) or a
    duck-typed tool object exposing it as ``.func``, and returns an
    Agents SDK ``FunctionTool`` with the same name and description whose
    every invocation is authorized by ACR first. When the Agents SDK is
    not installed, returns the guarded plain function instead.
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
    # The SDK derives a tool's description from the function docstring.
    # The guarded wrapper inherits the original docstring, which may be
    # empty even when the tool object carried a description; stamp the
    # resolved description on in that case (same fix as the CrewAI guard).
    if not inspect.getdoc(guarded):
        guarded.__doc__ = resolved_description
    try:
        from agents import function_tool
    except ImportError:
        return guarded
    # failure_error_function=None: ACR deny/escalate exceptions must reach
    # the caller as exceptions, not as tool-result text. The SDK's default
    # error function would convert them into a string the model sees as an
    # ordinary tool outcome.
    return function_tool(
        guarded,
        name_override=resolved_name,
        description_override=resolved_description,
        failure_error_function=None,
    )


def guard_openai_tools(
    tools: list[Any],
    *,
    session: ACRAgentSession,
    context_builder: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
    intent_builder: Callable[[dict[str, Any]], IntentRequest | dict[str, Any] | None] | None = None,
    execute_locally_on_allow: bool = True,
) -> list[Any]:
    """Guard a list of Agents SDK tools with the same session."""
    return [
        guard_openai_tool(
            tool_obj,
            session=session,
            context_builder=context_builder,
            intent_builder=intent_builder,
            execute_locally_on_allow=execute_locally_on_allow,
        )
        for tool_obj in tools
    ]
