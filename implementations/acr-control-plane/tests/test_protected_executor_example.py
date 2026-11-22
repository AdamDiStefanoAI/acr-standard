"""Smoke checks for the runnable, least-privilege executor example."""

from pathlib import Path
from unittest.mock import Mock

import pytest
from fastapi.testclient import TestClient

from acr.config import settings
from acr.gateway.executor_auth import build_brokered_execution_credential, build_execution_headers
from examples.protected_executor import app as executor_example
from examples.protected_executor.app import app


def test_executor_container_sets_unprivileged_runtime_user() -> None:
    dockerfile = Path(__file__).resolve().parents[1] / "examples/protected_executor/Dockerfile"
    instructions = [line.strip() for line in dockerfile.read_text().splitlines()]
    users = [line.split(maxsplit=1)[1] for line in instructions if line.startswith("USER ")]
    assert users and users[-1] not in {"root", "0", "root:root", "0:0"}
    ports = [line.split(maxsplit=1)[1] for line in instructions if line.startswith("EXPOSE ")]
    assert ports and all(int(port) >= 1024 for port in ports)


def test_executor_health_and_metadata_without_external_services(monkeypatch) -> None:
    monkeypatch.delenv("PROTECTED_EXECUTOR_ALLOWED_TOOLS", raising=False)
    with TestClient(app) as client:
        health = client.get("/health")
        metadata = client.get("/metadata")

    assert health.status_code == 200
    assert health.json() == {"status": "ok"}
    assert metadata.status_code == 200
    assert metadata.json() == {
        "executor": "acr-protected-executor",
        "exposed_tools": ["create_ticket", "issue_refund", "query_customer_db", "send_email"],
        "requires_gateway_execution_token": True,
        "requires_brokered_credential": True,
    }


def test_executor_exposes_only_configured_tools(monkeypatch) -> None:
    monkeypatch.setenv("PROTECTED_EXECUTOR_ALLOWED_TOOLS", "query_customer_db, unknown_tool")
    with TestClient(app) as client:
        metadata = client.get("/metadata")

    assert metadata.json()["exposed_tools"] == ["query_customer_db"]


def test_executor_denies_execution_without_gateway_credentials(monkeypatch) -> None:
    tool = Mock()
    monkeypatch.setitem(executor_example._ALLOWED_TOOLS, "query_customer_db", tool)
    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.post(
            "/execute",
            json={"tool_name": "query_customer_db", "parameters": {"customer_id": "C-12345"}},
        )

    assert response.status_code == 401
    assert response.json() == {
        "error_code": "INVALID_EXECUTION_AUTHORIZATION",
        "message": "X-ACR-Execution-Token header is required",
    }
    tool.assert_not_called()


@pytest.mark.parametrize(
    "case", ["allowed", "missing-brokered", "tampered-payload", "invalid-token"]
)
def test_executor_verifies_real_credentials_before_tool_execution(monkeypatch, case) -> None:
    monkeypatch.setattr(settings, "executor_hmac_secret", "test-execution-secret-" * 4)
    monkeypatch.setattr(settings, "executor_credential_secret", "test-credential-secret-" * 4)
    monkeypatch.setenv("PROTECTED_EXECUTOR_ALLOWED_TOOLS", "query_customer_db")
    tool = Mock(return_value={"customer_id": "C-12345"})
    monkeypatch.setitem(executor_example._ALLOWED_TOOLS, "query_customer_db", tool)
    payload = {"tool_name": "query_customer_db", "parameters": {"customer_id": "C-12345"}}
    headers = build_execution_headers(
        agent_id="executor-test",
        tool_name="query_customer_db",
        payload=payload,
        correlation_id="executor-test-call",
    )
    headers["X-ACR-Brokered-Credential"] = build_brokered_execution_credential(
        agent_id="executor-test",
        tool_name="query_customer_db",
        correlation_id="executor-test-call",
        audience="tool:query_customer_db",
        scopes=["tool:query_customer_db:execute"],
        payload=payload,
    )
    headers["X-ACR-Credential-Audience"] = "tool:query_customer_db"
    if case == "missing-brokered":
        headers.pop("X-ACR-Brokered-Credential")
    elif case == "tampered-payload":
        payload["parameters"]["customer_id"] = "C-99999"
    elif case == "invalid-token":
        headers["X-ACR-Execution-Token"] = "invalid"

    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.post("/execute", json=payload, headers=headers)

    if case == "allowed":
        assert response.status_code == 200
        assert response.json()["status"] == "executed"
        tool.assert_called_once_with(customer_id="C-12345")
    else:
        assert response.status_code == 401
        assert response.json()["error_code"] == "INVALID_EXECUTION_AUTHORIZATION"
        tool.assert_not_called()
