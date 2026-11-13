"""Static checks only: these do not execute n8n or the live Compose stack."""

import json
from pathlib import Path

EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "n8n"


def test_webhook_is_authenticated_and_inactive():
    workflow = json.loads((EXAMPLE / "acr_sensitive_action_workflow.json").read_text())
    assert workflow["active"] is False
    webhook = workflow["nodes"][0]
    assert webhook["type"] == "n8n-nodes-base.webhook"
    assert webhook["parameters"]["authentication"] == "headerAuth"
    assert webhook["parameters"]["responseMode"] == "responseNode"


def test_only_gateway_has_an_execution_path():
    workflow = json.loads((EXAMPLE / "acr_sensitive_action_workflow.json").read_text())
    assert len(workflow["nodes"]) == 3
    request = workflow["nodes"][1]["parameters"]
    assert request["url"] == "http://acr-gateway:8000/acr/evaluate"
    assert request["genericAuthType"] == "httpHeaderAuth"
    assert 'tool_name: "create_ticket"' in request["jsonBody"]
    assert 'agent_id: "n8n-support-demo"' in request["jsonBody"]
    assert "token" not in json.dumps(workflow).lower()
    assert workflow["nodes"][2]["parameters"]["responseBody"] == "={{ $json }}"
    assert workflow["connections"]["Agent Webhook"]["main"][0][0]["node"] == "ACR Evaluate"
    assert workflow["connections"]["ACR Evaluate"]["main"][0][0]["node"] == "Return ACR Decision"
