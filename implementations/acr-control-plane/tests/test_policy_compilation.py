"""Candidate compile failures cannot replace working policies or create artifacts."""

from __future__ import annotations

import os
import shutil
import subprocess
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from acr.common.errors import PolicyValidationError
from acr.db.models import PolicyReleaseRecord
from acr.policy_studio import compiler
from acr.policy_studio.core_bundle import export_bundle
from acr.policy_studio.releases import activate_policy_release, validate_policy_draft_record

OPA = os.environ.get("OPA_BINARY") or shutil.which("opa")


def test_export_missing_compiler_has_no_output(tmp_path, monkeypatch):
    monkeypatch.setenv("OPA_BINARY", str(tmp_path / "missing"))
    with pytest.raises(ValueError, match="OPA compiler unavailable"):
        export_bundle(tmp_path / "output")
    assert not (tmp_path / "output").exists()


def test_unsupported_compiler_version_is_explicit():
    compiler._check_version.cache_clear()
    with (
        patch.object(
            compiler.subprocess,
            "run",
            return_value=SimpleNamespace(returncode=0, stdout="Version: 1.0.0\n"),
        ),
        pytest.raises(ValueError, match="requires OPA 0.70.0"),
    ):
        compiler._check_version("/fake/opa", 0, 0)


def test_compiler_timeout_is_explicit_and_temp_cleaned(tmp_path, monkeypatch):
    monkeypatch.setattr(compiler.tempfile, "tempdir", str(tmp_path))
    compiler._compile.cache_clear()
    with (
        patch.object(compiler.subprocess, "run", side_effect=subprocess.TimeoutExpired("opa", 10)),
        pytest.raises(ValueError, match="could not complete"),
    ):
        compiler._compile(b"candidate", "/fake/opa", 0, 0)
    assert not list(tmp_path.iterdir())


@pytest.mark.skipif(not OPA, reason="requires real OPA")
def test_invalid_operator_export_keeps_existing_files(tmp_path):
    output = tmp_path / "output"
    export_bundle(output)
    original = {file.name: file.read_bytes() for file in output.iterdir()}
    extensions = tmp_path / "extensions"
    extensions.mkdir()
    (extensions / "bad.rego").write_text("package acr\ndeny contains x if {")
    with pytest.raises(ValueError, match="OPA rejected"):
        export_bundle(output, extensions, replace=True)
    assert {file.name: file.read_bytes() for file in output.iterdir()} == original


def stored(identifier, source, active=False):
    return PolicyReleaseRecord(
        release_id=identifier,
        draft_id="draft",
        agent_id="A",
        version=1,
        name="test",
        template="custom",
        manifest={},
        rego_policy=source,
        status="published",
        activation_status="active" if active else "inactive",
        active_bundle_uri="keep" if active else None,
    )


@pytest.mark.skipif(not OPA, reason="requires real OPA")
@pytest.mark.parametrize(
    "source",
    [
        "package acr\nallow if {",
        "package acr\nallow { missing_helper }",
        "package acr\nallow { data.acr.helper }",
    ],
)
async def test_invalid_replacement_does_not_deactivate_or_publish(db, source):
    old = stored("old", 'package acr\ndeny["old"] { true }', active=True)
    candidate = stored("new", source)
    db.add_all([old, candidate])
    await db.flush()
    with patch("acr.policy_studio.releases.publish_active_policy_bundle") as publish:
        with pytest.raises(PolicyValidationError):
            await activate_policy_release(db, release_id="new", actor="operator")
        publish.assert_not_called()
    assert old.activation_status == "active" and old.active_bundle_uri == "keep"
    assert candidate.activation_status == "inactive"
    assert candidate.rego_policy == source


@pytest.mark.skipif(not OPA, reason="requires real OPA")
def test_validate_reports_malformed_syntax():
    record = SimpleNamespace(
        agent_id="A",
        manifest={"agent_id": "A", "purpose": "test", "allowed_tools": ["query"]},
        wizard_inputs={},
        rego_policy="package acr\nallow if {",
    )
    response = validate_policy_draft_record(record)
    assert not response.valid and any("OPA rejected" in issue for issue in response.issues)


@pytest.mark.skipif(not OPA, reason="requires real OPA")
async def test_full_candidate_includes_other_agents_and_operator_extensions(
    db, tmp_path, monkeypatch
):
    from acr.config import settings

    old = stored("old", 'package acr\ndeny["old"] { true }', active=True)
    candidate = stored("new", 'package acr\ndeny["new"] { true }')
    other = stored("other", 'package acr\ndeny["other"] { missing_helper }', active=True)
    other.agent_id = "B"
    db.add_all([old, candidate, other])
    await db.flush()
    with (
        patch("acr.policy_studio.releases.publish_active_policy_bundle") as publish,
        pytest.raises(PolicyValidationError, match="OPA rejected"),
    ):
        await activate_policy_release(db, release_id="new", actor="operator")
    publish.assert_not_called()
    assert old.activation_status == "active" and candidate.activation_status == "inactive"
    other.rego_policy = 'package acr\ndeny["other"] { false }'
    await db.flush()
    (tmp_path / "conflict.rego").write_text("package acr\ndefault allow = true")
    monkeypatch.setattr(settings, "policy_extension_dir", str(tmp_path))
    with (
        patch("acr.policy_studio.releases.publish_active_policy_bundle") as publish,
        pytest.raises(PolicyValidationError, match="OPA rejected"),
    ):
        await activate_policy_release(db, release_id="new", actor="operator")
    publish.assert_not_called()
    assert old.activation_status == "active" and candidate.activation_status == "inactive"


@pytest.mark.skipif(not OPA, reason="requires real OPA")
async def test_validate_api_reports_syntax_error_and_publish_has_no_artifact(async_client):
    response = await async_client.post(
        "/acr/policy-drafts",
        json={
            "name": "invalid",
            "agent_id": "A",
            "template": "customer_support",
            "manifest": {"agent_id": "A", "purpose": "test", "allowed_tools": ["query"]},
            "rego_policy": "package acr\nallow if {",
            "wizard_inputs": {},
        },
    )
    assert response.status_code == 201
    draft = response.json()["draft_id"]
    validation = await async_client.get(f"/acr/policy-drafts/{draft}/validate")
    assert validation.status_code == 200 and validation.json()["valid"] is False
    assert any("OPA rejected" in issue for issue in validation.json()["issues"])
    with patch("acr.policy_studio.releases.publish_policy_bundle") as publish:
        result = await async_client.post(f"/acr/policy-drafts/{draft}/publish", json={})
    assert result.status_code >= 400
    publish.assert_not_called()
    assert (await async_client.get("/acr/policy-drafts/releases/history")).json() == []


@pytest.mark.skipif(not OPA, reason="requires real OPA")
async def test_read_only_preflight_checks_actual_stored_releases(db, monkeypatch):
    from contextlib import asynccontextmanager
    from unittest.mock import AsyncMock

    from acr.policy_studio.distribution import preflight_active_runtime

    current = stored("old", 'package acr\ndeny["old"] { true }', active=True)
    db.add(current)
    await db.flush()

    @asynccontextmanager
    async def factory():
        yield db

    monkeypatch.setattr("acr.db.database.async_session_factory", factory)
    with patch.object(db, "commit", new=AsyncMock()) as commit:
        result = await preflight_active_runtime()
        assert result["status"] == "valid" and result["active_release_count"] == 1
        commit.assert_not_awaited()
    assert current.activation_status == "active" and current.active_bundle_uri == "keep"
    current.rego_policy = "package acr\nallow { data.acr.helper }"
    await db.flush()
    with pytest.raises(ValueError, match="cannot reference data"):
        await preflight_active_runtime()
    assert current.activation_status == "active"
