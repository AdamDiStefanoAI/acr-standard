"""Real graph and SDK with synthetic HTTP decisions; no live policy validation."""

import pytest

pytest.importorskip("langgraph")

from examples.langgraph_refund.agent import APPROVAL_ID, main, run_scenario  # noqa: E402


@pytest.mark.parametrize(
    ("decision", "calls", "error", "approval_id"),
    [
        ("allow", [125.0], None, None),
        ("deny", [], "ACRDeniedError", None),
        ("escalate", [], "ACREscalatedError", APPROVAL_ID),
    ],
)
def test_refund_graph_outcomes(decision, calls, error, approval_id):
    outcome = run_scenario(decision)
    assert outcome["decision"] == decision
    assert outcome["calls"] == calls
    assert outcome["error"] == error
    assert outcome["approval_id"] == approval_id
    assert outcome["requests"] == ["/acr/evaluate"]
    expected = (
        {"status": "simulated", "amount": 125.0} if decision == "allow" else f"simulated {decision}"
    )
    assert outcome["result"] == expected


def test_console_displays_blocking_errors_and_synthetic_approval(capsys):
    main()
    output = capsys.readouterr().out
    assert "allow: fake_refund_calls=1" in output
    assert "deny: fake_refund_calls=0" in output
    assert "escalate: fake_refund_calls=0" in output
    assert "handled ACRDeniedError" in output
    assert "handled ACREscalatedError" in output
    assert f"approval_request_id={APPROVAL_ID}" in output


def test_unknown_scenario_fails():
    with pytest.raises(ValueError):
        run_scenario("unknown")
