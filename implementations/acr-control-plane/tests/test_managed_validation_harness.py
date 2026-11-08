"""Regression checks for the disposable lifecycle harness, not policy mocks."""

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest


@pytest.fixture
def harness(tmp_path, monkeypatch):
    path = Path(__file__).parents[1] / "scripts/managed_policy_validation.py"
    monkeypatch.chdir(tmp_path)
    spec = importlib.util.spec_from_file_location("managed_validation_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_repeated_policy_probes_reuse_one_issued_token(harness, monkeypatch):
    issued = []
    probes = []

    def request(method, path, body=None, headers=None):
        if path.endswith("/token"):
            issued.append(path)
            return 200, {"access_token": "synthetic-issued-token"}
        probes.append(headers)
        return 200, {"decision": "allow"}

    monkeypatch.setattr(harness, "request", request)
    for _ in range(30):
        assert harness.evaluate({"customer_id": "C-12345"})[0] == 200
    assert len(issued) == 1
    assert probes == [{"Authorization": "Bearer synthetic-issued-token"}] * 30


@pytest.mark.parametrize("status", [403, 429, 500, 503])
def test_policy_denial_or_dependency_failure_never_refreshes(harness, monkeypatch, status):
    issued = []

    def request(method, path, body=None, headers=None):
        if path.endswith("/token"):
            issued.append(path)
            return 200, {"access_token": "synthetic-issued-token"}
        return status, {"decision": "deny"}

    monkeypatch.setattr(harness, "request", request)
    for _ in range(15):
        assert harness.evaluate({})[0] == status
    assert len(issued) == 1


@pytest.mark.parametrize("retry_status", [200, 401])
def test_actual_authentication_failure_refreshes_once(harness, monkeypatch, retry_status):
    issued = []
    probes = []

    def request(method, path, body=None, headers=None):
        if path.endswith("/token"):
            issued.append(path)
            return 200, {"access_token": f"synthetic-token-{len(issued)}"}
        probes.append(headers)
        return (401 if len(probes) == 1 else retry_status), {}

    monkeypatch.setattr(harness, "request", request)
    assert harness.evaluate({})[0] == retry_status
    assert len(issued) == 2
    assert probes == [
        {"Authorization": "Bearer synthetic-token-1"},
        {"Authorization": "Bearer synthetic-token-2"},
    ]


def test_two_agents_cache_distinct_tokens(harness, monkeypatch):
    issued = []

    def request(method, path, body=None, headers=None):
        if path.endswith("/token"):
            issued.append(path)
            return 200, {"access_token": path.split("/")[-2]}
        assert headers == {"Authorization": "Bearer " + body["agent_id"]}
        return 200, {"decision": "allow"}

    monkeypatch.setattr(harness, "request", request)
    for _ in range(20):
        harness.evaluate({}, "upgrade-ci")
        harness.evaluate({}, "upgrade-ci-b")
    assert issued == ["/acr/agents/upgrade-ci/token", "/acr/agents/upgrade-ci-b/token"]


def test_fixture_refuses_caller_selected_executable(tmp_path):
    fixture = Path(__file__).parents[1] / "scripts/check_managed_policy_fixture.py"
    marker = tmp_path / "executed"
    executable = tmp_path / "untrusted-opa"
    executable.write_text(f"#!/bin/sh\ntouch {marker}\n")
    executable.chmod(0o755)
    result = subprocess.run(
        [sys.executable, str(fixture), "--opa", str(executable)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 2
    assert "unrecognized arguments: --opa" in result.stderr
    assert not marker.exists()
