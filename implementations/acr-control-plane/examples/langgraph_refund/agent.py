"""Offline compiled LangGraph refund demo. All decisions and effects are synthetic."""

from __future__ import annotations

import json
from typing import TypedDict

import httpx
from langgraph.graph import END, START, StateGraph

from acr.sdk import ACRAgentSession, ACRClient, ACRDeniedError, ACREscalatedError, guard_tool

APPROVAL_ID = "synthetic-refund-approval-001"


class RefundState(TypedDict):
    amount: float
    result: dict


def build_graph(session: ACRAgentSession, calls: list[float]):
    """Compile a real graph whose action node invokes the existing SDK guard."""

    def issue_refund(amount: float) -> dict:
        """Record a fake refund in memory, never contact a payment service."""
        calls.append(amount)
        return {"status": "simulated", "amount": amount}

    guarded_refund = guard_tool(issue_refund, session=session)

    def action(state: RefundState) -> dict:
        # Propagate blocking SDK exceptions. Never turn them into success.
        return {"result": guarded_refund(amount=state["amount"])}

    graph = StateGraph(RefundState)
    graph.add_node("refund", action)
    graph.add_edge(START, "refund")
    graph.add_edge("refund", END)
    return graph.compile()


def run_scenario(decision: str) -> dict:
    """Run one synthetic scenario with a real SDK and an HTTP-only mock."""
    if decision not in {"allow", "deny", "escalate"}:
        raise ValueError("Expected allow, deny, or escalate")
    calls: list[float] = []
    requests: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        # No live HTTP fallback: an unexpected request fails immediately.
        assert request.method == "POST"
        assert str(request.url) == "https://acr.invalid/acr/evaluate"
        assert request.headers["Authorization"] == "Bearer synthetic-offline-token"
        body = json.loads(request.content)
        assert body["agent_id"] == "refund-demo"
        assert body["action"]["tool_name"] == "issue_refund"
        assert body["action"]["parameters"] == {"amount": 125.0}
        assert calls == []  # Authorization precedes the fake side effect.
        requests.append(request.url.path)
        response = {"decision": decision, "reason": f"simulated {decision}"}
        if decision == "escalate":
            response["approval_request_id"] = APPROVAL_ID
        return httpx.Response(200, json=response)

    with ACRClient(
        base_url="https://acr.invalid", transport=httpx.MockTransport(handler)
    ) as client:
        session = client.create_agent_session("refund-demo", "synthetic-offline-token")
        graph = build_graph(session, calls)
        try:
            result = graph.invoke({"amount": 125.0, "result": {}})["result"]
            outcome = {"decision": decision, "result": result, "error": None, "approval_id": None}
        except (ACRDeniedError, ACREscalatedError) as exc:
            outcome = {
                "decision": exc.response.decision,
                "result": str(exc),
                "error": type(exc).__name__,
                "approval_id": exc.response.approval_request_id,
            }
    return {**outcome, "calls": calls, "requests": requests}


def main() -> None:
    for decision in ("allow", "deny", "escalate"):
        outcome = run_scenario(decision)
        print(f"{decision}: fake_refund_calls={len(outcome['calls'])}; result={outcome['result']}")
        if outcome["error"]:
            print(f"  handled {outcome['error']}")
        if outcome["approval_id"]:
            print(f"  approval_request_id={outcome['approval_id']}")


if __name__ == "__main__":
    main()
