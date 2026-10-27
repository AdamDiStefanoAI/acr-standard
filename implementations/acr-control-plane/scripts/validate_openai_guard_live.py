"""Four real gateway decisions through SDK tool callbacks; synthetic local effects.

Run only against a fresh disposable loopback gateway with execution disabled.
No model calls, approval resolution, replay, production actions, or audit-durability claims.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from acr.pillar1_identity.models import AgentRegisterRequest
from acr.sdk import ACRClient, ACRDeniedError, ACREscalatedError, guard_tool
from examples.openai_guard_example import _local_gateway_url, build_agent, invoke_agent_tool


def validate(client: ACRClient) -> list[dict[str, Any]]:
    agent_id = "openai-live-validation"
    client.register_agent(
        AgentRegisterRequest(
            agent_id=agent_id,
            owner="example@example.com",
            purpose="Disposable OpenAI SDK tool-boundary validation",
            allowed_tools=["query_customer_db", "send_email", "issue_refund"],
            forbidden_tools=["delete_customer"],
        )
    )
    session = client.issue_agent_session(agent_id)
    effects: list[dict[str, Any]] = []
    observations: list[dict[str, Any]] = []

    class ObservedSession:
        def evaluate_action(self, **kwargs):
            before = list(effects)
            response = session.evaluate_action(**kwargs)
            if effects != before:
                raise AssertionError("A local tool ran before authorization finished")
            if response.execution_result is not None:
                raise AssertionError("Gateway-side execution must be disabled")
            observations.append(
                {
                    "requested": kwargs,
                    "decision": response.decision,
                    "correlation_id": response.correlation_id,
                    "approval_request_id": response.approval_request_id,
                    "modified_action": response.modified_action.model_dump()
                    if response.modified_action is not None
                    else None,
                    "effects_before": before,
                }
            )
            return response

    def query_customer_db(customer_id: str) -> dict[str, str]:
        """Read a synthetic record in memory."""
        payload = {"customer_id": customer_id}
        effects.append({"tool": "query_customer_db", "parameters": payload})
        return payload

    def send_email(to: str, subject: str, body: str) -> dict[str, str]:
        """Record a synthetic email; never sends anything."""
        payload = {"to": to, "subject": subject, "body": body}
        effects.append({"tool": "send_email", "parameters": payload})
        return payload

    def delete_customer(customer_id: str) -> dict[str, str]:
        """Record a synthetic forbidden deletion in memory."""
        payload = {"customer_id": customer_id}
        effects.append({"tool": "delete_customer", "parameters": payload})
        return payload

    def issue_refund(customer_id: str, amount: float) -> dict[str, Any]:
        """Record a synthetic refund in memory; never transfers money."""
        payload = {"customer_id": customer_id, "amount": amount}
        effects.append({"tool": "issue_refund", "parameters": payload})
        return payload

    observed = ObservedSession()
    guarded = {
        tool.__name__: guard_tool(tool, session=observed, execute_locally_on_allow=False)
        for tool in (query_customer_db, send_email, delete_customer, issue_refund)
    }
    agent = build_agent(guarded)
    cases = [
        ("query_customer_db", {"customer_id": "C-100"}, "allow", None),
        (
            "send_email",
            {"to": "synthetic@example.com", "subject": "Demo", "body": "Synthetic message"},
            "modify",
            None,
        ),
        ("delete_customer", {"customer_id": "C-100"}, "deny", ACRDeniedError),
        ("issue_refund", {"customer_id": "C-100", "amount": 250.0}, "escalate", ACREscalatedError),
    ]
    for name, parameters, decision, expected_error in cases:
        before_count = len(effects)
        result = None
        try:
            result = invoke_agent_tool(agent, name, parameters)
        except (ACRDeniedError, ACREscalatedError) as exc:
            if expected_error is None or not isinstance(exc, expected_error):
                raise
        else:
            if expected_error is not None:
                raise AssertionError(f"{name}: expected {decision} to stop dispatch")
        observation = observations[-1]
        assert observation["decision"] == decision, observation
        assert observation["correlation_id"], observation
        observation["effects_after"] = list(effects)
        observation["tool_result"] = result
        if expected_error is not None:
            assert len(effects) == before_count, observation
        else:
            expected_parameters = (
                {**parameters, "to": "[REDACTED]"} if decision == "modify" else parameters
            )
            assert len(effects) == before_count + 1, observation
            assert effects[-1] == {"tool": name, "parameters": expected_parameters}, observation
            assert result == expected_parameters, observation
        if decision == "escalate":
            assert observation["approval_request_id"], observation
    assert len(observations) == 4
    assert len(effects) == 2
    return observations


def main() -> None:
    base_url = _local_gateway_url(os.environ.get("ACR_BASE_URL", "http://localhost:8000"))
    key = os.environ["ACR_OPERATOR_API_KEY"]
    with ACRClient(base_url=base_url, operator_api_key=key) as client:
        observations = validate(client)
    destination = Path(os.environ.get("ACR_GUARD_EVIDENCE", "openai-live-evidence.json"))
    destination.write_text(json.dumps(observations, indent=2) + "\n")
    print(
        "PASS: real gateway + real SDK dispatch; allow=1 modify=1 deny=0 escalate=0 local effects"
    )
    print("Pending approval was not resolved; no audit-persistence or full-conformance claim.")


if __name__ == "__main__":
    main()
