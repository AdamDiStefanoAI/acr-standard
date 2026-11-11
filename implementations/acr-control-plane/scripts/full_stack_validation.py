"""Full-stack HTTP acceptance checks; requires a disposable Compose project.
No imports from ACR, dependency overrides, mocks, LLM, or real enterprise tools.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import io
import json
import os
import subprocess
import time
import traceback
import urllib.error
import urllib.request
import zipfile
from http.client import HTTPException
from pathlib import Path

BASE = "http://127.0.0.1:8000"
EXECUTOR = "http://127.0.0.1:8010"
OUT = Path("full-stack-evidence")
OUT.mkdir(exist_ok=True)
OPERATOR = {"X-Operator-API-Key": "ci-operator-only"}
AGENT = "full-stack-ci"
records = []
correlations = []
auth = {}
# Bypass ambient proxies only for the fixed loopback targets.
http = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def request(method, path, body=None, headers=None, base=BASE):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        base + path,
        data=data,
        method=method,
        headers={"Content-Type": "application/json", **(headers or {})},
    )
    try:
        response = http.open(req, timeout=20)
    except urllib.error.HTTPError as exc:
        response = exc
    raw = response.read()
    try:
        payload = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        payload = None
    return response.status, payload, raw, dict(response.headers)


def ledger():
    status, data, _, _ = request("GET", "/__test/ledger", base=EXECUTOR)
    assert status == 200 and isinstance(data, list)
    return data


def evaluate(tool="query_customer_db", params=None):
    status, body, _, _ = request(
        "POST",
        "/acr/evaluate",
        {
            "agent_id": AGENT,
            "action": {"tool_name": tool, "parameters": params or {"customer_id": "C-12345"}},
        },
        auth,
    )
    if isinstance(body, dict) and body.get("correlation_id"):
        correlations.append(body["correlation_id"])
    return status, body


def observe(label, status, body, before, expected_count):
    after = ledger()
    assert len(after) == before + expected_count, (label, before, after)
    records.append(
        {
            "case": label,
            "status": status,
            "response": body,
            "before_count": before,
            "after_count": len(after),
            "new_side_effects": after[before:],
        }
    )
    (OUT / "observations.json").write_text(json.dumps(records, indent=2))


def preserve_failure(label):
    destination = OUT / "first-failure.log"
    if not destination.exists():
        destination.write_text(label + "\n" + traceback.format_exc())


def compose(*args):
    assert os.environ.get("COMPOSE_PROJECT_NAME", "").startswith("acr-fullstack-")
    subprocess.run(["docker", "compose", *args], check=True, timeout=60)


def decision(label, expected, params=None, tool="query_customer_db"):
    before = len(ledger())
    status, body = evaluate(tool, params)
    assert isinstance(body, dict) and body.get("decision") == expected, (label, status, body)
    assert status == {"allow": 200, "modify": 200, "deny": 403, "escalate": 202}[expected]
    observe(label, status, body, before, 1 if expected in {"allow", "modify"} else 0)
    if expected in {"allow", "modify"}:
        authorized = params or {"customer_id": "C-12345"}
        if expected == "modify":
            assert body["modified_action"]["tool_name"] == tool
            authorized = body["modified_action"]["parameters"]
        assert ledger()[before:] == [{"tool_name": tool, "parameters": authorized}]
    return body


def recovery(service):
    compose("start", service)
    deadline = time.monotonic() + 100
    before = len(ledger())
    while time.monotonic() < deadline:
        status, body = evaluate()
        if status == 200 and body.get("decision") == "allow":
            observe(service + "-recovered", status, body, before, 1)
            return
        assert len(ledger()) == before
        time.sleep(2)
    raise AssertionError(service + " did not recover within 100 seconds")


def wait_for_executor():
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        try:
            ledger()
            break
        except (urllib.error.URLError, OSError, HTTPException):
            time.sleep(1)
    else:
        raise AssertionError("Executor did not become ready within 60 seconds")


def jwt(claims, secret):
    def encoded(data):
        return base64.urlsafe_b64encode(json.dumps(data, separators=(",", ":")).encode()).rstrip(
            b"="
        )

    signing = encoded({"alg": "HS256", "typ": "JWT"}) + b"." + encoded(claims)
    signature = base64.urlsafe_b64encode(
        hmac.new(secret.encode(), signing, hashlib.sha256).digest()
    ).rstrip(b"=")
    return (signing + b"." + signature).decode()


def capture_evidence(correlation, expected, tool, parameters, prefix=""):
    """Retain a real persisted decision and its checksum-verified export."""
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        status, body, _, _ = request("GET", "/acr/events/" + correlation, headers=OPERATOR)
        if status == 200 and isinstance(body, list) and body:
            break
        time.sleep(1)
    assert status == 200 and isinstance(body, list) and body, (
        f"No audit event persisted for {expected} action"
    )
    assert any(
        event.get("request", {}).get("request_id") == correlation
        and event.get("agent", {}).get("agent_id") == AGENT
        and event.get("output", {}).get("decision") == expected
        and event.get("request", {}).get("tool_name") == tool
        and event.get("request", {}).get("parameters") == parameters
        for event in body
    )
    (OUT / f"{prefix}event-chain.json").write_text(json.dumps(body, indent=2))
    status, _, raw, headers = request("GET", "/acr/evidence/" + correlation, headers=OPERATOR)
    assert status == 200 and raw
    (OUT / f"{prefix}evidence-bundle.zip").write_bytes(raw)
    advertised = next(
        (v for k, v in headers.items() if k.lower() == "x-evidence-bundle-sha256"), None
    )
    assert hashlib.sha256(raw).hexdigest() == advertised
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        manifest = json.loads(archive.read("manifest.json"))
        events = [json.loads(line) for line in archive.read("events.jsonl").splitlines()]
        assert events == body, "Exported events differ from the fetched durable chain"
        assert manifest["correlation_id"] == correlation and manifest["agent_id"] == AGENT
        assert manifest["event_count"] == len(events) > 0 and expected in manifest["decisions"]
        assert any(
            event.get("request", {}).get("request_id") == correlation
            and event.get("agent", {}).get("agent_id") == AGENT
            and event.get("output", {}).get("decision") == expected
            and event.get("request", {}).get("tool_name") == tool
            and event.get("request", {}).get("parameters") == parameters
            for event in events
        )
        checked = set()
        for line in archive.read("checksums.sha256").decode().splitlines():
            digest, name = line.split(maxsplit=1)
            assert name in {"manifest.json", "events.jsonl"}
            assert name not in checked
            checked.add(name)
            assert hashlib.sha256(archive.read(name)).hexdigest() == digest
        assert checked == {"manifest.json", "events.jsonl"}


def run():
    global auth
    # Unauthorized caller must not register an agent.
    status, _, _, _ = request("POST", "/acr/agents", {"agent_id": "unauthorized"})
    assert status in {401, 403}
    manifest = {
        "agent_id": AGENT,
        "owner": "synthetic@example.invalid",
        "purpose": "Disposable full-stack checks",
        "risk_tier": "medium",
        "allowed_tools": ["query_customer_db", "issue_refund"],
        "forbidden_tools": ["delete_customer"],
        "boundaries": {"max_actions_per_minute": 200, "max_cost_per_hour_usd": 100},
    }
    status, body, _, _ = request("POST", "/acr/agents", manifest, OPERATOR)
    assert status == 201, (status, body)
    status, body, _, _ = request("POST", f"/acr/agents/{AGENT}/token", {}, OPERATOR)
    assert status == 200, (status, body)
    # Never print or persist the JWT.
    auth = {"Authorization": "Bearer " + body["access_token"]}
    decision("allow", "allow")
    denied = decision("deny", "deny", tool="delete_customer")
    denied_ledger = ledger()
    capture_evidence(
        denied["correlation_id"],
        "deny",
        "delete_customer",
        {"customer_id": "C-12345"},
        prefix="deny-",
    )
    assert ledger() == denied_ledger, "Evidence retrieval must not execute a denied tool"
    (OUT / "deny-ledger.json").write_text(json.dumps(denied_ledger, indent=2))
    original = "synthetic-person@example.invalid"
    modified = decision("modify", "modify", {"customer_id": original})
    executed = ledger()[-1]["parameters"]
    assert original not in json.dumps(executed)
    assert executed == modified["modified_action"]["parameters"]
    refund = {"customer_id": "C-12345", "amount": 250, "reason": "Synthetic fixture"}
    for resolution in ("approve", "deny"):
        pending = decision("escalate-" + resolution, "escalate", refund, "issue_refund")
        path = "/acr/approvals/" + pending["approval_request_id"]
        before = len(ledger())
        status, body, _, _ = request("GET", path, headers=OPERATOR)
        assert status == 200 and body["status"] == "pending"
        assert len(ledger()) == before
        status, body, _, _ = request(
            "POST", path + "/" + resolution, {"reason": "Synthetic test " + resolution}, OPERATOR
        )
        assert status == 200, (status, body)
        observe(resolution, status, body, before, 1 if resolution == "approve" else 0)
        if resolution == "approve":
            assert ledger()[-1] == {"tool_name": "issue_refund", "parameters": refund}
            before = len(ledger())
            successful_result = body["execution_result"]
            status, body, _, _ = request(
                "POST", path + "/approve", {"reason": "Repeat attempt"}, OPERATOR
            )
            assert status == 409
            observe("approval-replay", status, body, before, 0)
            status, receipt, _, _ = request("GET", path + "/receipt", headers=OPERATOR)
            assert status == 200 and receipt["state"] == "succeeded", (status, receipt)
            assert receipt["authorization_snapshot"]["approved_payload"]["parameters"] == refund
            status, resumed, _, _ = request("POST", path + "/execute", {}, OPERATOR)
            assert status == 200 and resumed["execution_result"] == successful_result
            observe("approval-resume-cached", status, resumed, before, 0)
            (OUT / "approval-execution-receipt.json").write_text(json.dumps(receipt, indent=2))
    before = len(ledger())
    status, body, _, _ = request(
        "POST", "/execute", {"tool_name": "query_customer_db", "parameters": {}}, base=EXECUTOR
    )
    assert status in {401, 403}
    observe("direct-bypass-rejected", status, body, before, 0)
    original_payload = {"tool_name": "query_customer_db", "parameters": {"customer_id": "C-12345"}}
    now = int(time.time())
    common = {
        "iss": "acr-control-plane",
        "agent_id": AGENT,
        "tool_name": "query_customer_db",
        "correlation_id": "synthetic-tamper-case",
        "approval_request_id": None,
        "iat": now,
        "nbf": now,
        "exp": now + 60,
    }
    headers = {
        "X-ACR-Execution-Token": jwt(
            {
                **common,
                "sub": "query_customer_db",
                "payload_sha256": hashlib.sha256(
                    json.dumps(original_payload, sort_keys=True, separators=(",", ":")).encode()
                ).hexdigest(),
            },
            os.environ["EXECUTOR_HMAC_SECRET"],
        ),
        "X-ACR-Brokered-Credential": jwt(
            {
                **common,
                "sub": "acr-executor:" + AGENT + ":query_customer_db",
                "aud": "tool:query_customer_db",
                "scopes": ["tool:query_customer_db:execute"],
            },
            os.environ["EXECUTOR_CREDENTIAL_SECRET"],
        ),
        "X-ACR-Credential-Audience": "tool:query_customer_db",
    }
    before = len(ledger())
    status, body, _, _ = request(
        "POST",
        "/execute",
        {**original_payload, "parameters": {"customer_id": "TAMPERED"}},
        headers,
        EXECUTOR,
    )
    assert status in {401, 403}
    observe("payload-tamper-rejected", status, body, before, 0)
    before = len(ledger())
    compose("stop", "protected-executor")
    try:
        status, body = evaluate()
        assert status >= 400
    except Exception:
        preserve_failure("executor outage")
        raise
    finally:
        compose("start", "protected-executor")
    wait_for_executor()
    observe("executor-outage", status, body, before, 0)
    decision("executor-recovered", "allow")
    for service in ("opa", "redis", "postgres"):
        compose("stop", service)
        try:
            before = len(ledger())
            status, body = evaluate()
            assert status >= 400, (service, status, body)
            observe(service + "-outage", status, body, before, 0)
        except Exception:
            preserve_failure(service + " outage")
            raise
        finally:
            recovery(service)
    # Reads intentionally use Redis, independent of the kill-service process.
    status, body, _, _ = request(
        "POST",
        "/acr/containment/kill",
        {"agent_id": AGENT, "reason": "Synthetic containment"},
        OPERATOR,
    )
    assert status == 200 and body["is_killed"]
    decision("contained", "deny")
    compose("stop", "acr-killswitch")
    try:
        decision("contained-while-kill-service-down", "deny")
        before = len(ledger())
        status, body, _, _ = request(
            "POST", "/acr/containment/restore", {"agent_id": AGENT}, OPERATOR
        )
        assert status >= 400
        observe("restore-service-outage", status, body, before, 0)
    except Exception:
        preserve_failure("kill-switch service outage")
        raise
    finally:
        compose("start", "acr-killswitch")
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        status, body, _, _ = request(
            "POST", "/acr/containment/restore", {"agent_id": AGENT}, OPERATOR
        )
        if status == 200 and not body["is_killed"]:
            break
        time.sleep(2)
    else:
        raise AssertionError("containment restore did not recover")
    decision("restored", "allow")
    capture_evidence(correlations[-1], "allow", "query_customer_db", {"customer_id": "C-12345"})
    (OUT / "ledger.json").write_text(json.dumps(ledger(), indent=2))
    print("PASS: real full-stack checks; enterprise side effects are synthetic fixture only")


if __name__ == "__main__":
    try:
        run()
    except Exception:
        preserve_failure("full-stack validation")
        raise
    finally:
        (OUT / "observations.json").write_text(json.dumps(records, indent=2))
