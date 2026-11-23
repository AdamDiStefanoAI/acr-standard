"""Unit checks for the red-team harness categories 3-10.

The harness itself runs against a live stack (CI: acr-red-team.yml);
these tests drive each new category runner against a fake gateway
that implements the recon'd behavior of the real one (identity
binding, approval lifecycle, kill switch, decision records, drift
baseline governance, executor ledger) and pin the verdict logic:
pass when the fake stack blocks the attack, fail when a deliberately
weakened fake lets it through, inconclusive when a precondition
cannot be established. No network, no Docker.
"""

import importlib.util
import json
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest


@pytest.fixture(scope="module")
def harness():
    path = Path(__file__).parents[1] / "scripts/red_team_harness.py"
    spec = importlib.util.spec_from_file_location("red_team_harness_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FakeGateway:
    """A miniature, correct-by-default ACR stack behind the harness's
    http()/_executor_http() seams. Weakened variants flip one flag to
    prove the corresponding probe reports a fail, not a pass."""

    def __init__(self, harness, degraded=False):
        self.h = harness
        self.degraded = degraded
        self.agents = {}  # agent_id -> {"allowed_tools": [...]}
        self.killed = set()
        self.approvals = {}  # rid -> dict
        self.decisions = []  # {"correlation_id", "agent_id", "decision"}
        self.ledger = []  # {"tool_name", "parameters"}
        self.drift_samples = {}  # agent_id -> int
        self.drift_points = {}  # agent_id -> deviation points since freeze
        self.drift_frozen = set()
        self._rid = 0
        # Weakening flags for negative tests.
        self.allow_mismatch = False
        self.replay_reexecutes = False

    # ── helpers ──────────────────────────────────────────────────────
    def _operator_ok(self, headers):
        return headers.get("X-Operator-API-Key") == self.h.OPERATOR_KEY

    def _unauthorized(self):
        return 401, {"error_code": "UNAUTHORIZED_OPERATOR"}, {}

    def _record_decision(self, corr, agent_id, decision):
        self.decisions.append({"correlation_id": corr, "agent_id": agent_id, "decision": decision})

    def _execute(self, approval):
        self.ledger.append(
            {"tool_name": approval["tool_name"], "parameters": dict(approval["parameters"])}
        )
        approval["executed"] = True
        approval["execution_result"] = {"status": "executed"}

    # ── gateway http seam ────────────────────────────────────────────
    def http(self, method, path, body=None, headers=None):
        headers = headers or {}
        parsed = urlparse(path)
        route, query = parsed.path, parse_qs(parsed.query)
        parts = [p for p in route.split("/") if p]

        if route == "/acr/ready":
            if self.degraded:
                return (
                    503,
                    {
                        "status": "not_ready",
                        "checks": {"database": "ok", "redis": "ok", "opa": "error"},
                    },
                    {},
                )
            return (
                200,
                {"status": "ready", "checks": {"database": "ok", "redis": "ok", "opa": "ok"}},
                {},
            )
        if route == "/acr/live":
            return 200, {"status": "alive"}, {}
        if route == "/acr/agents" and method == "POST":
            if not self._operator_ok(headers):
                return self._unauthorized()
            agent_id = body["agent_id"]
            if agent_id in self.agents:
                return 409, {"error_code": "AGENT_ALREADY_EXISTS"}, {}
            self.agents[agent_id] = {"allowed_tools": list(body["allowed_tools"])}
            return 201, {"agent_id": agent_id}, {}
        if len(parts) == 3 and parts[:2] == ["acr", "agents"]:
            agent_id = parts[2]
            if method == "GET":
                if not self._operator_ok(headers):
                    return self._unauthorized()
                if agent_id not in self.agents:
                    return 404, {}, {}
                return (
                    200,
                    {"agent_id": agent_id, "allowed_tools": self.agents[agent_id]["allowed_tools"]},
                    {},
                )
            if method == "PUT":
                if not self._operator_ok(headers):
                    return self._unauthorized()
                return 200, {"agent_id": agent_id}, {}
            if method == "DELETE":
                if not self._operator_ok(headers):
                    return self._unauthorized()
                self.agents.pop(agent_id, None)
                return 204, {}, {}
        if len(parts) == 4 and parts[:2] == ["acr", "agents"] and parts[3] == "token":
            if not self._operator_ok(headers):
                return self._unauthorized()
            if parts[2] not in self.agents:
                return 404, {"error_code": "AGENT_NOT_FOUND"}, {}
            return 200, {"access_token": f"tok-{parts[2]}", "expires_in_seconds": 1800}, {}
        if route == "/acr/evaluate" and method == "POST":
            return self._evaluate(body or {}, headers)
        if route == "/acr/approvals" and method == "GET":
            if not self._operator_ok(headers):
                return self._unauthorized()
            return 200, [a for a in self.approvals.values() if a["status"] == "pending"], {}
        if len(parts) >= 3 and parts[:2] == ["acr", "approvals"]:
            return self._approval_route(method, parts, body, headers)
        if route == "/acr/containment/kill" and method == "POST":
            if not self._operator_ok(headers):
                return self._unauthorized()
            self.killed.add(body["agent_id"])
            return 200, {"agent_id": body["agent_id"], "is_killed": True}, {}
        if route == "/acr/containment/restore" and method == "POST":
            if not self._operator_ok(headers):
                return self._unauthorized()
            self.killed.discard(body["agent_id"])
            return 200, {"agent_id": body["agent_id"], "is_killed": False}, {}
        if len(parts) == 4 and parts[:2] == ["acr", "containment"] and parts[2] == "status":
            if not self._operator_ok(headers):
                return self._unauthorized()
            return 200, {"agent_id": parts[3], "is_killed": parts[3] in self.killed}, {}
        if route == "/acr/decisions" and method == "GET":
            if not self._operator_ok(headers):
                return self._unauthorized()
            items = self.decisions
            if "correlation_id" in query:
                items = [d for d in items if d["correlation_id"] == query["correlation_id"][0]]
            if "agent_id" in query:
                items = [d for d in items if d["agent_id"] == query["agent_id"][0]]
            limit = int(query.get("limit", ["50"])[0])
            return (
                200,
                {"items": items[:limit], "total": len(items), "limit": limit, "offset": 0},
                {},
            )
        if len(parts) == 3 and parts[:2] == ["acr", "events"] and method == "GET":
            if not self._operator_ok(headers):
                return self._unauthorized()
            events = [
                {"event_type": "policy_decision"}
                for d in self.decisions
                if d["correlation_id"] == parts[2]
            ]
            return 200, events, {}
        if len(parts) == 3 and parts[:2] == ["acr", "evidence"] and method == "GET":
            if not self._operator_ok(headers):
                return self._unauthorized()
            return 200, {}, {}
        if route == "/acr/evidence-packages" and method == "POST":
            if not self._operator_ok(headers):
                return self._unauthorized()
            return 200, {}, {}
        if len(parts) == 3 and parts[:2] == ["acr", "drift"] and method == "GET":
            if not self._operator_ok(headers):
                return self._unauthorized()
            agent_id = parts[2]
            samples = self.drift_samples.get(agent_id, 0)
            points = self.drift_points.get(agent_id, 0)
            score = min(0.95, 0.15 * points) if agent_id in self.drift_frozen else 0.0
            return (
                200,
                {
                    "agent_id": agent_id,
                    "score": score,
                    "signals": [],
                    "sample_count": samples,
                    "is_baseline_ready": samples >= 10,
                },
                {},
            )
        if "baseline" in parts and parts[:2] == ["acr", "drift"]:
            if not self._operator_ok(headers):
                return self._unauthorized()
            agent_id = parts[2]
            if route.endswith("/propose"):
                return (
                    200,
                    {"baseline_version_id": "bv-1", "agent_id": agent_id, "status": "proposed"},
                    {},
                )
            if route.endswith("/approve"):
                return 200, {"baseline_version_id": "bv-1", "status": "approved"}, {}
            if route.endswith("/activate"):
                self.drift_frozen.add(agent_id)
                return 200, {"baseline_version_id": "bv-1", "status": "active"}, {}
        return 404, {"error_code": "NOT_FOUND"}, {}

    def _approval_route(self, method, parts, body, headers):
        rid = parts[2]
        action = parts[3] if len(parts) > 3 else None
        if not self._operator_ok(headers):
            return self._unauthorized()
        approval = self.approvals.get(rid)
        if approval is None:
            return 404, {"error_code": "APPROVAL_NOT_FOUND"}, {}
        if method == "GET" and action is None:
            return 200, dict(approval), {}
        if method == "GET" and action == "receipt":
            if approval.get("executed"):
                return 200, {"payload_hash": "deadbeef", "state": "succeeded"}, {}
            return 404, {"error_code": "NO_RECEIPT"}, {}
        if method == "POST" and action == "approve":
            if approval["status"] != "pending":
                return 409, {"error_code": "APPROVAL_CONFLICT"}, {}
            approval["status"] = "approved"
            if approval["agent_id"] in self.killed:
                return 409, {"error_code": "APPROVAL_CONFLICT"}, {}
            self._execute(approval)
            return 200, dict(approval), {}
        if method == "POST" and action == "deny":
            if approval["status"] != "pending":
                return 409, {"error_code": "APPROVAL_CONFLICT"}, {}
            approval["status"] = "denied"
            return 200, dict(approval), {}
        if method == "POST" and action == "override":
            if not (body or {}).get("reason"):
                return 422, {"error_code": "REASON_REQUIRED"}, {}
            if approval["status"] != "pending":
                return 409, {"error_code": "APPROVAL_CONFLICT"}, {}
            approval["status"] = "overridden"
            self._execute(approval)
            return 200, dict(approval), {}
        if method == "POST" and action == "execute":
            if approval["status"] not in ("approved", "overridden"):
                return 409, {"error_code": "APPROVAL_CONFLICT"}, {}
            if approval["agent_id"] in self.killed:
                return 409, {"error_code": "APPROVAL_CONFLICT"}, {}
            if approval.get("executed") and not self.replay_reexecutes:
                return 200, dict(approval), {}
            self._execute(approval)
            return 200, dict(approval), {}
        return 404, {"error_code": "NOT_FOUND"}, {}

    def _evaluate(self, body, headers):
        corr = headers.get("X-Correlation-ID", "corr")
        agent_id = body.get("agent_id")
        auth = headers.get("Authorization", "")
        bearer = auth.removeprefix("Bearer ") if auth.startswith("Bearer ") else None
        if not bearer or not bearer.startswith("tok-"):
            return 401, {"error_code": "INVALID_TOKEN"}, {}
        token_agent = bearer.removeprefix("tok-")
        if token_agent != agent_id and not self.allow_mismatch:
            return (
                403,
                {"decision": "deny", "error_code": "AGENT_ID_MISMATCH", "correlation_id": corr},
                {},
            )
        if self.degraded:
            return 503, {"error_code": "POLICY_ENGINE_ERROR"}, {}
        if agent_id not in self.agents:
            return 403, {"error_code": "AGENT_NOT_REGISTERED"}, {}
        if agent_id in self.killed:
            self._record_decision(corr, agent_id, "deny")
            return (
                403,
                {"decision": "deny", "error_code": "AGENT_KILLED", "correlation_id": corr},
                {},
            )
        action = body.get("action") or {}
        tool = action.get("tool_name")
        params = action.get("parameters") or {}
        self.drift_samples[agent_id] = self.drift_samples.get(agent_id, 0) + 1
        blob = json.dumps(params)
        decision, status = "allow", 200
        if (
            "rm -rf" in blob
            or tool in ("delete_customer", "query_billing_db")
            or (tool == "send_email" and "123-45-6789" in blob)
        ):
            decision, status = "deny", 403
        elif tool == "issue_refund" and (params.get("amount") or 0) > 100:
            decision, status = "escalate", 202
        if agent_id in self.drift_frozen and decision != "allow":
            self.drift_points[agent_id] = self.drift_points.get(agent_id, 0) + 2
        elif agent_id in self.drift_frozen and tool != "query_customer_db":
            self.drift_points[agent_id] = self.drift_points.get(agent_id, 0) + 1
        self._record_decision(corr, agent_id, decision)
        resp = {"decision": decision, "correlation_id": corr}
        if decision == "escalate":
            self._rid += 1
            rid = f"apr-fake-{self._rid}"
            self.approvals[rid] = {
                "request_id": rid,
                "agent_id": agent_id,
                "tool_name": tool,
                "parameters": dict(params),
                "status": "pending",
                "execution_result": None,
                "executed": False,
            }
            resp["approval_request_id"] = rid
        elif decision == "allow" and tool in ("query_customer_db", "issue_refund"):
            self.ledger.append({"tool_name": tool, "parameters": dict(params)})
        return status, resp, {}

    # ── executor http seam ───────────────────────────────────────────
    def executor_http(self, method, path, body=None, headers=None):
        if method == "GET" and path == "/__test/ledger":
            return 200, list(self.ledger)
        if method == "POST" and path == "/execute":
            # The harness never holds a genuine gateway credential in
            # these tests; every direct attempt is a forgery.
            return 403, {"error_code": "INVALID_EXECUTION_AUTHORIZATION"}
        return 404, {}


@pytest.fixture()
def stack(harness, monkeypatch):
    fake = FakeGateway(harness)
    monkeypatch.setattr(harness, "http", fake.http)
    monkeypatch.setattr(harness, "_executor_http", fake.executor_http)
    records = []
    harness.register_agent()
    return fake, records


def verdicts(records):
    return {r["probe"]: r["verdict"] for r in records}


def test_category_3_approval_all_pass(harness, stack):
    fake, records = stack
    harness.run_category_3(harness.TokenManager(), records.append)
    v = verdicts(records)
    assert set(v) == {
        "3.0-control",
        "3.1-no-transfer",
        "3.2-replay-execute",
        "3.3-double-decision",
        "3.4-agent-self-approve",
        "3.5-cross-agent",
        "3.6-payload-edit",
        "3.7-override-guards",
    }
    assert all(x == "pass" for x in v.values()), v
    # Exactly three executions: R1 approve, B's approve, the $150 snapshot.
    refunds = [e for e in fake.ledger if e["tool_name"] == "issue_refund"]
    assert len(refunds) == 3


def test_category_3_replay_reexecution_is_a_fail(harness, stack):
    fake, records = stack
    fake.replay_reexecutes = True
    harness.run_category_3(harness.TokenManager(), records.append)
    assert verdicts(records)["3.2-replay-execute"] == "fail"


def test_category_4_identity_all_pass(harness, stack):
    fake, records = stack
    harness.run_category_4(harness.TokenManager(), records.append)
    v = verdicts(records)
    assert len(v) == 9
    assert all(x == "pass" for x in v.values()), v


def test_category_4_mismatch_allowed_is_a_fail(harness, stack):
    fake, records = stack
    fake.allow_mismatch = True
    harness.run_category_4(harness.TokenManager(), records.append)
    v = verdicts(records)
    assert v["4.1-token-for-other-agent"] == "fail"
    assert v["4.2-other-token-for-agent"] == "fail"


def test_category_5_evidence_all_pass(harness, stack):
    fake, records = stack
    harness.run_category_5(harness.TokenManager(), records.append)
    v = verdicts(records)
    assert len(v) == 5
    assert all(x == "pass" for x in v.values()), v
    burst = next(r for r in records if r["probe"] == "5.5-burst-completeness")
    assert len(burst["submitted"]) == 25
    assert burst["missing_correlation_ids"] == []


def test_category_6_killswitch_all_pass(harness, stack):
    fake, records = stack
    harness.run_category_6(harness.TokenManager(), records.append)
    v = verdicts(records)
    assert len(v) == 8
    assert all(x == "pass" for x in v.values()), v
    assert harness.AGENT_ID not in fake.killed  # restored by 6.7


def test_category_7_broker_all_pass(harness, stack):
    fake, records = stack
    harness.run_category_7(harness.TokenManager(), records.append)
    v = verdicts(records)
    assert len(v) == 7
    assert all(x == "pass" for x in v.values()), v
    # Only the gateway-mediated control executed.
    assert len(fake.ledger) == 1


def test_category_8_drift_all_pass(harness, stack):
    fake, records = stack
    harness.run_category_8(harness.TokenManager(), records.append)
    v = verdicts(records)
    assert len(v) == 3
    assert all(x == "pass" for x in v.values()), v
    sharp = next(r for r in records if r["probe"] == "8.3-sharp-deviation")
    assert sharp["baseline_frozen"] is True
    assert sharp["trajectory"][-1]["score"] > sharp["trajectory"][0]["score"]


def test_category_9_injection_all_pass(harness, stack):
    fake, records = stack
    harness.run_category_9(harness.TokenManager(), records.append)
    v = verdicts(records)
    assert len(v) == 7
    assert all(x == "pass" for x in v.values()), v


def test_category_10_degraded_all_pass(harness, monkeypatch):
    fake = FakeGateway(harness, degraded=True)
    monkeypatch.setattr(harness, "http", fake.http)
    monkeypatch.setattr(harness, "_executor_http", fake.executor_http)
    records = []
    harness.register_agent()
    harness.run_category_10(harness.TokenManager(), records.append)
    v = verdicts(records)
    assert len(v) == 6
    assert all(x == "pass" for x in v.values()), v
    assert fake.ledger == []  # nothing executed while degraded


def test_category_10_not_degraded_is_inconclusive(harness, stack):
    fake, records = stack
    harness.run_category_10(harness.TokenManager(), records.append)
    v = verdicts(records)
    assert all(x == "inconclusive" for x in v.values()), v


def test_evidence_record_shape(harness, stack):
    _, records = stack
    harness.run_category_9(harness.TokenManager(), records.append)
    for rec in records:
        for key in (
            "category",
            "probe",
            "hypothesis",
            "input",
            "expected",
            "http_status",
            "decision",
            "correlation_id",
            "verdict",
        ):
            assert key in rec, (rec["probe"], key)
        assert rec["category"] == "9"
        assert rec["verdict"] in ("pass", "fail", "inconclusive")


def test_runner_and_env_gating(harness):
    assert set(harness.RUNNERS) == {str(i) for i in range(1, 12)}
    assert set(harness.IMPLEMENTED) == set(harness.RUNNERS)
    assert harness.CATEGORY_ENV["10"] == ("REDTEAM_DEGRADED",)
    assert harness.CATEGORY_ENV["11"] == ("MCP_GATEWAY_URL", "MCP_FIXTURE_URL")


def test_forge_jwt_shapes(harness):
    forged = harness.forge_jwt({"sub": "agent-x"}, secret="wrong")
    assert forged.count(".") == 2
    none_token = harness.forge_jwt({"sub": "agent-x"}, alg="none")
    assert none_token.endswith(".")
    assert none_token.count(".") == 2


def test_canonical_payload_sha256(harness):
    import hashlib

    payload = {"b": 1, "a": {"y": [1, 2], "x": "s"}}
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    assert (
        harness.canonical_payload_sha256(payload) == hashlib.sha256(canonical.encode()).hexdigest()
    )
