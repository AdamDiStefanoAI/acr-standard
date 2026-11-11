"""Exact-evaluation identity binding for approvals; no live OPA required."""

from __future__ import annotations

import hashlib
import io
import tarfile
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from acr.pillar2_policy.engine import evaluate_policy
from acr.policy_studio.core_bundle import (
    assemble_bundle,
    canonical_json,
    core_identity,
    managed_core_files,
    operator_identity,
    validate_extension,
)
from acr.policy_studio.distribution import (
    build_active_runtime_bundle,
    expected_policy_identity,
    studio_release_identity,
)


def release(**changes):
    return SimpleNamespace(
        **(
            {
                "agent_id": "agent-a",
                "release_id": "release-a",
                "version": 1,
                "rego_policy": "package acr\nallow := true",
            }
            | changes
        )
    )


def test_studio_identity_tracks_content_version_and_membership():
    first = studio_release_identity([release()])
    for change in (
        {"release_id": "release-b"},
        {"version": 2},
        {"rego_policy": "package acr\nallow := false"},
        {"agent_id": "agent-b"},
    ):
        assert studio_release_identity([release(**change)]) != first
    assert studio_release_identity([]) != first
    a, b = release(), release(agent_id="agent-b", release_id="release-b")
    assert studio_release_identity([a, b]) == studio_release_identity([b, a])
    with pytest.raises(ValueError, match="Multiple active"):
        studio_release_identity([a, a])


@pytest.mark.parametrize("studio", [None, "invalid", 12, {}])
async def test_legacy_or_malformed_marker_cannot_bind_approval(studio):
    opa = {
        "core_identity": core_identity(),
        "operator_identity": operator_identity(),
        "studio_identity": studio,
        "allow": True,
    }
    with patch(
        "acr.pillar2_policy.engine.opa_breaker.call_async",
        new=AsyncMock(return_value={"result": opa}),
    ):
        result = await evaluate_policy({}, {}, {})
    assert result.final_decision == "allow"  # Existing evaluation API remains compatible.
    assert result.policy_identity is None


async def test_exact_evaluation_identity_detects_unloaded_active_release():
    old = studio_release_identity([])
    opa = {
        "core_identity": core_identity(),
        "operator_identity": operator_identity(),
        "studio_identity": old,
        "escalate": True,
    }
    with patch(
        "acr.pillar2_policy.engine.opa_breaker.call_async",
        new=AsyncMock(return_value={"result": opa}),
    ):
        result = await evaluate_policy({}, {}, {})
    with patch(
        "acr.policy_studio.releases.list_active_policy_releases", new=AsyncMock(return_value=[])
    ):
        assert result.policy_identity == await expected_policy_identity(None)
    with patch(
        "acr.policy_studio.releases.list_active_policy_releases",
        new=AsyncMock(return_value=[release()]),
    ):
        assert result.policy_identity != await expected_policy_identity(None)


def test_empty_bundle_has_explicit_studio_identity():
    with (
        patch("acr.policy_studio.core_bundle.file_rego_version", return_value=0),
        patch("acr.policy_studio.core_bundle.validate_bundle"),
    ):
        bundle, _ = assemble_bundle(managed_core_files())
    with tarfile.open(fileobj=io.BytesIO(bundle), mode="r:gz") as archive:
        marker = archive.extractfile("bundle/studio_identity.rego").read().decode()
    assert hashlib.sha256(canonical_json([])).hexdigest() in marker


def test_operator_cannot_override_studio_marker():
    with pytest.raises(ValueError, match="reserved"):
        validate_extension('package acr\nstudio_identity := "fake"', name="unsafe.rego")


def test_active_bundle_marker_matches_expected_release_set():
    record = release(activated_at=None)
    with (
        patch("acr.policy_studio.core_bundle.file_rego_version", return_value=0),
        patch("acr.policy_studio.core_bundle.validate_bundle"),
    ):
        artifact = build_active_runtime_bundle([record])
    with tarfile.open(fileobj=io.BytesIO(artifact.bytes_data), mode="r:gz") as archive:
        marker = archive.extractfile("bundle/studio_identity.rego").read().decode()
    assert studio_release_identity([record]) in marker


async def test_real_opa_identity_matches_current_database(db, tmp_path):
    """Compile/evaluate an actual archive, then parse exactly that OPA response."""
    import json
    import os
    import shutil
    import subprocess

    from acr.db.models import PolicyReleaseRecord

    opa = os.environ.get("OPA_BINARY") or shutil.which("opa")
    if not opa:
        pytest.skip("requires supported OPA 0.70.0 compiler")
    record = PolicyReleaseRecord(
        release_id="release-real",
        draft_id="draft-real",
        agent_id="agent-a",
        version=1,
        name="identity test",
        template="custom",
        manifest={},
        rego_policy='package acr\nescalate { input.action.tool_name == "issue_refund" }',
        status="published",
        activation_status="active",
    )
    db.add(record)
    await db.flush()
    artifact = build_active_runtime_bundle([record])
    archive = tmp_path / "active.tar.gz"
    archive.write_bytes(artifact.bytes_data)
    policy_input = {
        "agent": {"agent_id": "agent-a", "allowed_tools": ["issue_refund"]},
        "action": {"tool_name": "issue_refund", "parameters": {}},
        "context": {},
    }
    evaluated = subprocess.run(
        [opa, "eval", "--bundle", str(archive), "--stdin-input", "--format=json", "data.acr"],
        input=json.dumps(policy_input),
        capture_output=True,
        text=True,
        check=True,
        timeout=10,
    )
    result = json.loads(evaluated.stdout)["result"][0]["expressions"][0]["value"]
    expected = await expected_policy_identity(db)
    assert result["core_identity"] == expected["core"]
    assert result["operator_identity"] == expected["operator"]
    assert result["studio_identity"] == expected["studio"]
    with patch(
        "acr.pillar2_policy.engine.opa_breaker.call_async",
        new=AsyncMock(return_value={"result": result}),
    ):
        parsed = await evaluate_policy(
            **{
                "agent_manifest": policy_input["agent"],
                "action": policy_input["action"],
                "context": policy_input["context"],
            }
        )
    assert parsed.policy_identity == expected
    assert parsed.final_decision == "escalate"
    record.activation_status = "inactive"
    await db.flush()
    assert parsed.policy_identity != await expected_policy_identity(db)
