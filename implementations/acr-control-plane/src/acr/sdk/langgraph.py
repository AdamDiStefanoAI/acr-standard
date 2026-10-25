"""LangGraph/LangChain-style tool guards built on top of the ACR SDK."""

from __future__ import annotations

import inspect
from collections.abc import Callable
from functools import wraps
from typing import Any

from acr.gateway.models import EvaluateResponse, IntentRequest
from acr.sdk.client import ACRAgentSession, AsyncACRAgentSession
from acr.sdk.errors import ACRDeniedError, ACREscalatedError, ACRSDKError


def _bind_arguments(func: Callable[..., Any], *args: Any, **kwargs: Any) -> dict[str, Any]:
    bound = inspect.signature(func).bind(*args, **kwargs)
    bound.apply_defaults()
    return dict(bound.arguments)


def _coerce_intent(intent: IntentRequest | dict[str, Any] | None) -> IntentRequest | None:
    if intent is None:
        return None
    return IntentRequest.model_validate(intent)


def _resolve_effective_parameters(
    original_parameters: dict[str, Any],
    response: EvaluateResponse,
    tool_name: str,
) -> dict[str, Any]:
    if response.modified_action is None:
        if response.decision == "modify":
            raise ACRSDKError("MODIFY response requires an explicit modified action")
        return original_parameters
    if response.modified_action.tool_name != tool_name:
        raise ACRSDKError("Modified action does not match the guarded tool")
    if "parameters" not in response.modified_action.model_fields_set:
        raise ACRSDKError("Modified action requires explicit parameters")
    return dict(response.modified_action.parameters)


def _handle_blocking_decision(response: EvaluateResponse) -> None:
    if response.decision == "deny":
        raise ACRDeniedError(response)
    if response.decision == "escalate":
        raise ACREscalatedError(response)


def guard_tool(
    func: Callable[..., Any],
    *,
    session: ACRAgentSession,
    tool_name: str | None = None,
    description: str | None = None,
    context_builder: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
    intent_builder: Callable[[dict[str, Any]], IntentRequest | dict[str, Any] | None] | None = None,
    execute_locally_on_allow: bool = True,
) -> Callable[..., Any]:
    """
    Wrap a local tool so ACR authorizes it before execution.

    This works well for LangGraph/LangChain tool functions even when the graph
    itself is not tightly coupled to ACR-specific logic.
    """
    resolved_tool_name = tool_name or func.__name__
    resolved_description = description or inspect.getdoc(func)

    @wraps(func)
    def wrapped(*args: Any, **kwargs: Any) -> Any:
        parameters = _bind_arguments(func, *args, **kwargs)
        context = context_builder(parameters) if context_builder else {}
        intent = _coerce_intent(intent_builder(parameters)) if intent_builder else None
        response = session.evaluate_action(
            tool_name=resolved_tool_name,
            parameters=parameters,
            description=resolved_description,
            context=context,
            intent=intent,
        )
        _handle_blocking_decision(response)
        effective_parameters = _resolve_effective_parameters(
            parameters, response, resolved_tool_name
        )
        if response.execution_result is not None and not execute_locally_on_allow:
            return response.execution_result
        return func(**effective_parameters)

    return wrapped


def guard_async_tool(
    func: Callable[..., Any],
    *,
    session: AsyncACRAgentSession,
    tool_name: str | None = None,
    description: str | None = None,
    context_builder: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
    intent_builder: Callable[[dict[str, Any]], IntentRequest | dict[str, Any] | None] | None = None,
    execute_locally_on_allow: bool = True,
) -> Callable[..., Any]:
    """Async version of ``guard_tool`` for coroutine-based LangGraph tools."""
    resolved_tool_name = tool_name or func.__name__
    resolved_description = description or inspect.getdoc(func)

    @wraps(func)
    async def wrapped(*args: Any, **kwargs: Any) -> Any:
        parameters = _bind_arguments(func, *args, **kwargs)
        context = context_builder(parameters) if context_builder else {}
        intent = _coerce_intent(intent_builder(parameters)) if intent_builder else None
        response = await session.evaluate_action(
            tool_name=resolved_tool_name,
            parameters=parameters,
            description=resolved_description,
            context=context,
            intent=intent,
        )
        _handle_blocking_decision(response)
        effective_parameters = _resolve_effective_parameters(
            parameters, response, resolved_tool_name
        )
        if response.execution_result is not None and not execute_locally_on_allow:
            return response.execution_result
        result = func(**effective_parameters)
        if inspect.isawaitable(result):
            return await result
        return result

    return wrapped


def build_langchain_tool(
    func: Callable[..., Any],
    *,
    session: ACRAgentSession | AsyncACRAgentSession,
    name: str | None = None,
    description: str | None = None,
    context_builder: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
    intent_builder: Callable[[dict[str, Any]], IntentRequest | dict[str, Any] | None] | None = None,
    execute_locally_on_allow: bool = True,
):
    """
    Optional helper that returns a LangChain StructuredTool when
    ``langchain-core`` is installed.
    """
    try:
        from langchain_core.tools import StructuredTool
    except ImportError as exc:  # pragma: no cover - exercised by users, not CI
        raise RuntimeError(
            "langchain-core is not installed. Install the integration extra or "
            "add langchain-core to your environment."
        ) from exc

    resolved_name = name or func.__name__
    resolved_description = (
        description or inspect.getdoc(func) or f"Guarded ACR tool: {resolved_name}"
    )

    if isinstance(session, AsyncACRAgentSession):
        coroutine = guard_async_tool(
            func,
            session=session,
            tool_name=resolved_name,
            description=resolved_description,
            context_builder=context_builder,
            intent_builder=intent_builder,
            execute_locally_on_allow=execute_locally_on_allow,
        )
        return StructuredTool.from_function(
            coroutine=coroutine,
            name=resolved_name,
            description=resolved_description,
        )

    wrapped = guard_tool(
        func,
        session=session,
        tool_name=resolved_name,
        description=resolved_description,
        context_builder=context_builder,
        intent_builder=intent_builder,
        execute_locally_on_allow=execute_locally_on_allow,
    )
    return StructuredTool.from_function(
        func=wrapped,
        name=resolved_name,
        description=resolved_description,
    )
