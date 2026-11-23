"""LangGraph guard test matrix: streaming, async dispatch, retry paths.

Complements tests/test_langgraph_example.py (compiled-graph invoke /
ainvoke dispatch) with the paths that file does not cover:

- tool-level and graph-level streaming (``stream`` / ``astream``), where
  the guard must evaluate exactly once before any streamed output and a
  deny must surface before the tool body runs;
- native async tools (coroutine functions) dispatched by ToolNode;
- LangGraph retry paths: a ToolNode retry policy re-invokes the tool,
  and every attempt passes through the guard again — a transient tool
  failure can recover only through a fresh evaluation, and a deny cannot
  be worn down by retries (the tool body never executes).

Sessions are duck-typed fakes that count evaluations; no network or live
gateway is involved. The module skips cleanly when langgraph is not
installed, like the example test module.
"""

from __future__ import annotations

from typing import Any, cast

import pytest

pytest.importorskip("langgraph")

from langchain_core.messages import AIMessage, ToolMessage  # noqa: E402
from langgraph.graph import END, START, MessagesState, StateGraph  # noqa: E402
from langgraph.prebuilt import ToolNode  # noqa: E402
from langgraph.types import RetryPolicy  # noqa: E402

from acr.gateway.models import EvaluateResponse  # noqa: E402
from acr.sdk.client import ACRAgentSession, AsyncACRAgentSession  # noqa: E402
from acr.sdk.errors import ACRDeniedError  # noqa: E402
from acr.sdk.langgraph import build_langchain_tool  # noqa: E402


class _Session:
    """Sync fake session: queued responses, then the last one repeats."""

    def __init__(self, *responses: EvaluateResponse) -> None:
        self._responses = list(responses) or [EvaluateResponse(decision="allow")]
        self.calls: list[dict[str, Any]] = []

    def evaluate_action(self, **kwargs):
        self.calls.append(kwargs)
        if len(self._responses) > 1:
            return self._responses.pop(0)
        return self._responses[0]


class _AsyncSession:
    def __init__(self, *responses: EvaluateResponse) -> None:
        self._responses = list(responses) or [EvaluateResponse(decision="allow")]
        self.calls: list[dict[str, Any]] = []

    async def evaluate_action(self, **kwargs):
        self.calls.append(kwargs)
        if len(self._responses) > 1:
            return self._responses.pop(0)
        return self._responses[0]


def _graph(tools, *, retry_policy: RetryPolicy | None = None):
    graph = StateGraph(MessagesState)
    node = ToolNode(tools, handle_tool_errors=False)
    if retry_policy is not None:
        graph.add_node("tools", node, retry_policy=retry_policy)
    else:
        graph.add_node("tools", node)
    graph.add_edge(START, "tools")
    graph.add_edge("tools", END)
    return graph.compile()


def _call(name: str, args: dict[str, Any]) -> dict:
    return {
        "messages": [
            AIMessage(
                content="",
                tool_calls=[{"name": name, "args": args, "id": "matrix-call"}],
            )
        ]
    }


def _streamed_messages(events) -> list[Any]:
    """Collect messages from langgraph stream events (updates mode nests
    each node's state update under the node name)."""
    messages: list[Any] = []
    for event in events:
        if not isinstance(event, dict):
            continue
        for value in event.values():
            if isinstance(value, dict):
                messages.extend(value.get("messages", []))
    return messages


def _file_report_factory(effects: list[str]):
    def file_report(title: str) -> str:
        """File a demo report in memory."""
        effects.append(title)
        return f"filed: {title}"

    return file_report


class TestStreaming:
    def test_tool_stream_evaluates_once_before_output(self) -> None:
        effects: list[str] = []
        session = _Session()
        tool = build_langchain_tool(
            _file_report_factory(effects), session=cast(ACRAgentSession, session)
        )
        chunks = list(tool.stream({"title": "streamed"}))
        assert chunks, "stream must yield the tool result"
        assert effects == ["streamed"]
        assert len(session.calls) == 1

    def test_tool_stream_deny_produces_no_output_and_no_effect(self) -> None:
        effects: list[str] = []
        session = _Session(EvaluateResponse(decision="deny", reason="no streaming"))
        tool = build_langchain_tool(
            _file_report_factory(effects), session=cast(ACRAgentSession, session)
        )
        with pytest.raises(ACRDeniedError, match="no streaming"):
            list(tool.stream({"title": "streamed"}))
        assert effects == []

    def test_graph_stream_allow_and_deny(self) -> None:
        effects: list[str] = []
        session = _Session(
            EvaluateResponse(decision="allow"),
            EvaluateResponse(decision="deny", reason="graph stream deny"),
        )
        tool = build_langchain_tool(
            _file_report_factory(effects), session=cast(ACRAgentSession, session)
        )
        graph = _graph([tool])
        events = list(graph.stream(_call("file_report", {"title": "one"})))
        messages = _streamed_messages(events)
        assert any(isinstance(m, ToolMessage) and m.content == "filed: one" for m in messages)
        assert effects == ["one"]
        with pytest.raises(ACRDeniedError, match="graph stream deny"):
            list(graph.stream(_call("file_report", {"title": "two"})))
        assert effects == ["one"]
        assert len(session.calls) == 2

    async def test_graph_astream_with_async_session(self) -> None:
        effects: list[str] = []
        session = _AsyncSession()
        tool = build_langchain_tool(
            _file_report_factory(effects),
            session=cast(AsyncACRAgentSession, session),
        )
        graph = _graph([tool])
        events = [
            event async for event in graph.astream(_call("file_report", {"title": "async-one"}))
        ]
        seen = _streamed_messages(events)
        assert any(isinstance(m, ToolMessage) and m.content == "filed: async-one" for m in seen)
        assert effects == ["async-one"]
        assert len(session.calls) == 1


class TestAsyncToolDispatch:
    async def test_native_async_tool_runs_through_toolnode(self) -> None:
        effects: list[str] = []

        async def fetch_status(service: str) -> str:
            """Fetch a service status asynchronously."""
            effects.append(service)
            return f"status: {service} ok"

        session = _AsyncSession()
        tool = build_langchain_tool(fetch_status, session=cast(AsyncACRAgentSession, session))
        graph = _graph([tool])
        result = await graph.ainvoke(_call("fetch_status", {"service": "api"}))
        message = result["messages"][-1]
        assert isinstance(message, ToolMessage)
        assert message.content == "status: api ok"
        assert effects == ["api"]
        assert len(session.calls) == 1

    async def test_native_async_tool_deny_never_executes(self) -> None:
        effects: list[str] = []

        async def fetch_status(service: str) -> str:
            """Fetch a service status asynchronously."""
            effects.append(service)
            return f"status: {service} ok"

        session = _AsyncSession(EvaluateResponse(decision="deny", reason="async deny"))
        tool = build_langchain_tool(fetch_status, session=cast(AsyncACRAgentSession, session))
        graph = _graph([tool])
        with pytest.raises(ACRDeniedError, match="async deny"):
            await graph.ainvoke(_call("fetch_status", {"service": "api"}))
        assert effects == []


class TestRetryPaths:
    def test_transient_failure_recovers_only_through_fresh_evaluation(self) -> None:
        attempts: list[str] = []

        def flaky_lookup(key: str) -> str:
            """Fail transiently once, then succeed."""
            attempts.append(key)
            if len(attempts) == 1:
                raise ConnectionError("transient downstream failure")
            return f"value: {key}"

        session = _Session()  # allow on every evaluation
        tool = build_langchain_tool(flaky_lookup, session=cast(ACRAgentSession, session))
        graph = _graph(
            [tool],
            retry_policy=RetryPolicy(max_attempts=3, retry_on=ConnectionError),
        )
        result = graph.invoke(_call("flaky_lookup", {"key": "k1"}))
        message = result["messages"][-1]
        assert isinstance(message, ToolMessage)
        assert message.content == "value: k1"
        # Two tool attempts, and the guard evaluated BOTH: a retry never
        # rides on the first attempt's authorization.
        assert attempts == ["k1", "k1"]
        assert len(session.calls) == 2

    def test_deny_is_not_retried_by_default_policy_and_never_executes(self) -> None:
        effects: list[str] = []
        session = _Session(EvaluateResponse(decision="deny", reason="always denied"))
        tool = build_langchain_tool(
            _file_report_factory(effects), session=cast(ACRAgentSession, session)
        )
        graph = _graph([tool], retry_policy=RetryPolicy(max_attempts=3))
        with pytest.raises(ACRDeniedError, match="always denied"):
            graph.invoke(_call("file_report", {"title": "retry-me"}))
        # LangGraph's default retry_on treats RuntimeError subclasses
        # (ACRDeniedError included) as non-transient, so the deny is not
        # retried at all. Either way the tool body never ran.
        assert effects == []
        assert len(session.calls) == 1

    def test_deny_cannot_be_worn_down_by_retries(self) -> None:
        effects: list[str] = []
        session = _Session(EvaluateResponse(decision="deny", reason="always denied"))
        tool = build_langchain_tool(
            _file_report_factory(effects), session=cast(ACRAgentSession, session)
        )
        # Even a policy that explicitly retries denials gains nothing:
        # every attempt is evaluated fresh and denied before execution.
        graph = _graph(
            [tool],
            retry_policy=RetryPolicy(max_attempts=3, retry_on=ACRDeniedError),
        )
        with pytest.raises(ACRDeniedError, match="always denied"):
            graph.invoke(_call("file_report", {"title": "retry-me"}))
        assert effects == []
        assert len(session.calls) == 3

    def test_allow_then_deny_on_retry_blocks_second_execution(self) -> None:
        attempts: list[str] = []

        def flaky_lookup(key: str) -> str:
            """Fail transiently once, then would succeed."""
            attempts.append(key)
            if len(attempts) == 1:
                raise ConnectionError("transient downstream failure")
            return f"value: {key}"

        session = _Session(
            EvaluateResponse(decision="allow"),
            EvaluateResponse(decision="deny", reason="policy changed mid-flight"),
        )
        tool = build_langchain_tool(flaky_lookup, session=cast(ACRAgentSession, session))
        graph = _graph(
            [tool],
            retry_policy=RetryPolicy(max_attempts=3, retry_on=ConnectionError),
        )
        with pytest.raises(ACRDeniedError, match="policy changed mid-flight"):
            graph.invoke(_call("flaky_lookup", {"key": "k1"}))
        # The first attempt executed (and failed transiently); the retry
        # was evaluated fresh, denied, and never executed.
        assert attempts == ["k1"]
        assert len(session.calls) == 2
