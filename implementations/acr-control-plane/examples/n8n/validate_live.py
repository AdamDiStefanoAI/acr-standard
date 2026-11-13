"""Real n8n/webhook/gateway/executor checks against disposable CI services only."""

import json
import os
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).parent
HTTP = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def request(port, path, body=None, headers=None):
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}",
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Content-Type": "application/json", **(headers or {})},
    )
    try:
        response = HTTP.open(req, timeout=30)
    except urllib.error.HTTPError as exc:
        response = exc
    raw = response.read()
    try:
        data = json.loads(raw)
    except ValueError:
        data = raw.decode()
    return response.status, data


def compose(*args):
    subprocess.run(["docker", "compose", *args], check=True, timeout=180)


def main():
    assert os.environ.get("COMPOSE_PROJECT_NAME", "").startswith("acr-n8n-")
    operator = {"X-Operator-API-Key": "ci-operator-only"}
    status, body = request(
        8000,
        "/acr/agents",
        {
            "agent_id": "n8n-support-demo",
            "owner": "demo@example.invalid",
            "purpose": "Synthetic customer-support ticket demo",
            "allowed_tools": ["create_ticket"],
            "forbidden_tools": ["delete_customer"],
        },
        operator,
    )
    assert status in (200, 201), (status, body)
    status, token = request(8000, "/acr/agents/n8n-support-demo/token", {}, operator)
    assert status == 200, (status, token)
    folder = ROOT / ".ci-input"
    folder.mkdir(exist_ok=True)
    credentials = [
        {
            "id": "acrWebhookDemo",
            "name": "Synthetic webhook key",
            "type": "httpHeaderAuth",
            "data": {"name": "X-Demo-Key", "value": "ci-webhook-only"},
        },
        {
            "id": "acrAgentDemo",
            "name": "Synthetic agent JWT",
            "type": "httpHeaderAuth",
            "data": {"name": "Authorization", "value": "Bearer " + token["access_token"]},
        },
    ]
    (folder / "credentials.json").write_text(json.dumps(credentials))
    workflow = json.loads((ROOT / "acr_sensitive_action_workflow.json").read_text())
    workflow["id"] = "acrN8nDemo"
    for index, credential in ((0, credentials[0]), (1, credentials[1])):
        workflow["nodes"][index]["credentials"] = {
            "httpHeaderAuth": {"id": credential["id"], "name": credential["name"]}
        }
    (folder / "workflow.json").write_text(json.dumps(workflow))
    compose(
        "run",
        "--rm",
        "--no-deps",
        "n8n",
        "import:credentials",
        "--input=/fixtures/credentials.json",
    )
    compose("run", "--rm", "--no-deps", "n8n", "import:workflow", "--input=/fixtures/workflow.json")
    compose("run", "--rm", "--no-deps", "n8n", "publish:workflow", "--id=acrN8nDemo")
    compose("up", "-d", "n8n")
    for _attempt in range(60):
        try:
            if request(5678, "/healthz")[0] == 200:
                break
        except (OSError, TimeoutError):
            pass
        time.sleep(2)
    else:
        raise AssertionError("n8n did not become healthy")
    time.sleep(3)
    records = []
    for name, payload, headers, decision, delta in [
        (
            "allow",
            {
                "subject": "Synthetic follow-up",
                "tool_name": "delete_customer",
                "agent_id": "attacker",
                "customer_id": "attacker",
            },
            {"X-Demo-Key": "ci-webhook-only"},
            "allow",
            1,
        ),
        ("deny", {"subject": "rm -rf /"}, {"X-Demo-Key": "ci-webhook-only"}, "deny", 0),
        ("missing-webhook-key", {"subject": "Synthetic follow-up"}, {}, None, 0),
    ]:
        before = request(8011, "/__test/ledger")[1]
        status, response = request(5678, "/webhook/acr-sensitive-action", payload, headers)
        after = request(8011, "/__test/ledger")[1]
        assert len(after) == len(before) + delta, (name, before, after)
        if decision:
            assert status == 200 and response["decision"] == decision, (name, status, response)
        else:
            assert status in (401, 403), (name, status, response)
        if decision == "allow":
            assert response.get("execution_result"), response
            assert after[-1]["subject"] == payload["subject"], after
            assert after[-1]["customer_id"] == "C-N8N-SYNTHETIC", after
        records.append(
            {
                "case": name,
                "status": status,
                "decision": decision,
                "before_count": len(before),
                "after_count": len(after),
            }
        )
    out = Path("n8n-evidence")
    out.mkdir(exist_ok=True)
    (out / "observations.json").write_text(json.dumps(records, indent=2))
    print(json.dumps(records, indent=2))


if __name__ == "__main__":
    main()
