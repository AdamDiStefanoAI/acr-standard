"""Managed policy identity, deterministic delivery, migration, and fail-closed checks."""

from __future__ import annotations

import copy
import io
import json
import os
import shutil
import subprocess
import tarfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from acr.common.errors import PolicyEngineError
from acr.pillar2_policy.engine import evaluate_policy
from acr.policy_studio.core_bundle import (
    assemble_bundle,
    core_identity,
    core_sources,
    export_bundle,
    extension_files,
    managed_core_files,
    opa_config,
    operator_identity,
)
from acr.policy_studio.distribution import build_active_runtime_bundle


def test_shipped_resources_match_reviewed_sources():
    policies = Path(__file__).parents[1] / "policies" / "acr"
    for name, contents in core_sources().items():
        assert contents == (policies / name).read_bytes()


def test_deterministic_archive_and_manifest(tmp_path):
    first = export_bundle(tmp_path / "one")
    second = export_bundle(tmp_path / "two")
    assert first == second
    assert (tmp_path / "one/bundle.tar.gz").read_bytes() == (
        tmp_path / "two/bundle.tar.gz"
    ).read_bytes()
    with tarfile.open(tmp_path / "one/bundle.tar.gz") as archive:
        manifest = json.load(archive.extractfile(".manifest"))
        assert manifest["revision"] == first["revision"]
        assert manifest["roots"] == ["acr"]
        assert all(member.mtime == 0 for member in archive.getmembers())
    assert first["core"] == core_identity()


def test_extensions_preserved_and_core_overrides_rejected(tmp_path):
    ext = tmp_path / "extensions"
    ext.mkdir()
    custom = (
        b'package acr\ndeny contains "operator deny" if { input.action.tool_name == "custom" }\n'
    )
    (ext / "custom.rego").write_bytes(custom)
    for name, contents in core_sources().items():
        (ext / name).write_bytes(contents)
    assert extension_files(ext) == {"bundle/extensions/custom.rego": custom}
    export_bundle(tmp_path / "out", ext)
    assert (ext / "custom.rego").read_bytes() == custom
    (ext / "common.rego").write_text("package acr\nallow := true\n")
    with pytest.raises(ValueError, match="Modified legacy core"):
        export_bundle(tmp_path / "next", ext)


@pytest.mark.parametrize(
    "source",
    [
        "package acr\ncore_identity := {}",
        'package acr\n__acr_core_files["common.rego"] := "forged"',
        "package other\nallow := true",
    ],
)
def test_reserved_extensions_rejected(tmp_path, source):
    (tmp_path / "custom.rego").write_text(source)
    with pytest.raises(ValueError):
        extension_files(tmp_path)


def test_configmap_symlink_projection_and_escape(tmp_path):
    root = tmp_path / "mount"
    backing = root / "..2026"
    backing.mkdir(parents=True)
    (backing / "custom.rego").write_text('package acr\ndeny contains "custom" if { true }')
    (root / "..data").symlink_to("..2026", target_is_directory=True)
    (root / "custom.rego").symlink_to("..data/custom.rego")
    assert list(extension_files(root)) == ["bundle/extensions/custom.rego"]
    (root / "escape.rego").symlink_to(tmp_path / "outside.rego")
    with pytest.raises(ValueError, match="escapes"):
        extension_files(root)


def test_export_requires_explicit_replace_and_keeps_unrelated_files(tmp_path):
    export_bundle(tmp_path)
    (tmp_path / "operator.txt").write_text("keep me")
    with pytest.raises(ValueError, match="overwrite"):
        export_bundle(tmp_path, gateway_url="http://new-gateway:8000")
    export_bundle(tmp_path, gateway_url="http://new-gateway:8000", replace=True)
    assert (tmp_path / "operator.txt").read_text() == "keep me"


def test_config_pins_core_and_auth_without_discovery():
    config = opa_config("http://gateway:8000/")
    assert "discovery" not in config
    assert config["services"]["acr_control_plane"]["headers"] == {
        "X-Operator-API-Key": "${ACR_BUNDLE_API_KEY}"
    }
    assert core_identity()["core_id"] in config["bundles"]["acr_active_runtime"]["resource"]


def release(agent, version=1):
    return SimpleNamespace(
        agent_id=agent,
        release_id=f"release-{agent}-{version}",
        version=version,
        activated_at=None,
        rego_policy='package acr\ndeny contains "dynamic" if {\n input.action.tool_name == "dynamic"\n}\n',
    )


def test_active_release_order_stable_and_activation_changes_revision(tmp_path):
    one, two = release("one"), release("two")
    first = build_active_runtime_bundle([one, two])
    assert first.bytes_data == build_active_runtime_bundle([two, one]).bytes_data
    assert first.sha256 != build_active_runtime_bundle([one]).sha256
    (tmp_path / "custom.rego").write_text('package acr\ndeny contains "custom" if { true }')
    bundle = build_active_runtime_bundle([one], extensions=str(tmp_path))
    with tarfile.open(fileobj=io.BytesIO(bundle.bytes_data)) as archive:
        assert "bundle/extensions/custom.rego" in archive.getnames()
        scoped = archive.extractfile("bundle/agents/one.rego").read()
        assert b'input.agent.agent_id == "one"' in scoped


@pytest.mark.parametrize(
    "change", ["missing", "stale", "contract", "missing-module", "mixed-module"]
)
async def test_every_decision_rejects_untrusted_core(change):
    identity = copy.deepcopy(core_identity())
    if change == "missing":
        identity = None
    elif change == "stale":
        identity["core_id"] = "old"
    elif change == "contract":
        identity["contract_version"] = 999
    elif change == "missing-module":
        del identity["files"]["content_safety.rego"]
    else:
        identity["files"]["common.rego"] = "old"
    for decision in ("allow", "modify", "escalate"):
        with (
            patch(
                "acr.pillar2_policy.engine.opa_breaker.call_async",
                new=AsyncMock(return_value={"result": {decision: True, "core_identity": identity}}),
            ),
            pytest.raises(PolicyEngineError, match="managed core"),
        ):
            await evaluate_policy({}, {}, {})


async def test_current_core_decisions_work_without_separate_probe():
    with patch(
        "acr.pillar2_policy.engine.opa_breaker.call_async",
        new=AsyncMock(
            return_value={
                "result": {
                    "allow": True,
                    "core_identity": core_identity(),
                    "operator_identity": operator_identity(),
                }
            }
        ),
    ) as call:
        assert (await evaluate_policy({}, {}, {})).final_decision == "allow"
        assert call.await_count == 1


async def test_version_qualified_endpoint_rejects_mismatch(async_client):
    current = core_identity()["core_id"]
    assert (
        await async_client.get(f"/acr/policy-bundles/{current}/active.tar.gz")
    ).status_code == 200
    assert (await async_client.get("/acr/policy-bundles/old/active.tar.gz")).status_code == 404


OPA = os.environ.get("OPA_BINARY") or shutil.which("opa")


@pytest.mark.skipif(not OPA, reason="set OPA_BINARY to run real OPA checks")
@pytest.mark.parametrize("mutation", ["none", "missing", "mixed"])
def test_real_opa_identity_and_content_guardrail(tmp_path, mutation):
    payloads = managed_core_files()
    if mutation == "missing":
        del payloads["bundle/content_safety.rego"]
    elif mutation == "mixed":
        payloads["bundle/content_safety.rego"] = payloads["bundle/content_safety.rego"].replace(
            core_identity()["files"]["content_safety.rego"].encode(), b"old-module-hash"
        )
    archive, _ = assemble_bundle(payloads)
    bundle = tmp_path / "bundle.tar.gz"
    bundle.write_bytes(archive)
    request = {
        "agent": {
            "allowed_tools": ["shell"],
            "forbidden_tools": [],
            "boundaries": {"max_actions_per_minute": 10, "max_cost_per_hour_usd": 10},
        },
        "action": {"tool_name": "shell", "parameters": {"command": "rm -rf /"}},
        "context": {},
    }
    input_path = tmp_path / "input.json"
    input_path.write_text(json.dumps(request))
    process = subprocess.run(
        [OPA, "eval", "-b", str(bundle), "-i", str(input_path), "--format=json", "data.acr"],
        text=True,
        capture_output=True,
        check=True,
    )
    value = json.loads(process.stdout)["result"][0]["expressions"][0]["value"]
    if mutation == "none":
        assert value["core_identity"] == core_identity()
        assert value["deny"]
        assert value["allow"] is False
    else:
        assert value["core_identity"] != core_identity()


async def test_changed_operator_configuration_denies_until_bundle_loaded(tmp_path, monkeypatch):
    from acr.config import settings

    (tmp_path / "custom.rego").write_text('package acr\ndeny contains "custom" if { true }')
    monkeypatch.setattr(settings, "policy_extension_dir", str(tmp_path))
    stale = {
        "allow": True,
        "core_identity": core_identity(),
        "operator_identity": operator_identity(),
    }
    with (
        patch(
            "acr.pillar2_policy.engine.opa_breaker.call_async",
            new=AsyncMock(return_value={"result": stale}),
        ),
        pytest.raises(PolicyEngineError, match="operator policy"),
    ):
        await evaluate_policy({}, {}, {})
    stale["operator_identity"] = operator_identity(tmp_path)
    with patch(
        "acr.pillar2_policy.engine.opa_breaker.call_async",
        new=AsyncMock(return_value={"result": stale}),
    ):
        assert (await evaluate_policy({}, {}, {})).final_decision == "allow"


def test_draft_validation_rejects_reserved_runtime_metadata():
    from acr.policy_studio.releases import validate_policy_draft_record

    draft = SimpleNamespace(
        agent_id="test",
        manifest={"agent_id": "test", "purpose": "test", "allowed_tools": ["shell"]},
        wizard_inputs={},
        rego_policy='package acr\noperator_identity := "forged"',
    )
    validation = validate_policy_draft_record(draft)
    assert not validation.valid
    assert any("reserved" in issue for issue in validation.issues)


@pytest.mark.skipif(not OPA, reason="set OPA_BINARY to run real OPA checks")
def test_real_opa_release_and_operator_policy_survive_core_upgrade_rollback(tmp_path, monkeypatch):
    from acr.policy_studio import core_bundle

    ext = tmp_path / "ext"
    ext.mkdir()
    (ext / "custom.rego").write_text(
        'package acr\ndeny contains "local operator" if { input.action.tool_name == "custom" }'
    )
    original = core_sources()
    old = core_identity()
    observed = []
    for index, upgrade in enumerate((False, True, False)):
        sources = {
            **original,
            "content_safety.rego": original["content_safety.rego"]
            + (b"\n# next release\n" if upgrade else b""),
        }
        monkeypatch.setattr(core_bundle, "core_sources", lambda sources=sources: sources)
        expected = core_identity()
        bundle = tmp_path / f"release-{index}.tar.gz"
        bundle.write_bytes(
            build_active_runtime_bundle([release("agent")], extensions=str(ext)).bytes_data
        )
        for tool, reason in (("dynamic", "dynamic"), ("custom", "local operator")):
            request = {
                "agent": {
                    "agent_id": "agent",
                    "allowed_tools": [tool],
                    "forbidden_tools": [],
                    "boundaries": {},
                },
                "action": {"tool_name": tool, "parameters": {}},
                "context": {},
            }
            input_path = tmp_path / "input.json"
            input_path.write_text(json.dumps(request))
            result = subprocess.run(
                [
                    OPA,
                    "eval",
                    "-b",
                    str(bundle),
                    "-i",
                    str(input_path),
                    "--format=json",
                    "data.acr",
                ],
                text=True,
                capture_output=True,
                check=True,
            )
            value = json.loads(result.stdout)["result"][0]["expressions"][0]["value"]
            assert reason in value["deny"]
            assert value["core_identity"] == expected
            assert value["operator_identity"] == operator_identity(ext)
        observed.append(expected)
    assert observed[0] == observed[2] == old
    assert observed[1] != old


@pytest.mark.parametrize(
    "name",
    [
        "data.json",
        "data.yaml",
        "data.yml",
        ".manifest",
        "policy.tar.gz",
        "archive.zip",
        "unknown.txt",
    ],
)
@pytest.mark.parametrize("projected", [False, True])
def test_unsupported_operator_data_refused_before_export(tmp_path, name, projected):
    root = tmp_path / "extensions"
    root.mkdir()
    source = root / "..2026" if projected else root
    source.mkdir(exist_ok=True)
    (source / "custom.rego").write_text('package acr\ndeny contains "block" if { true }')
    (source / name).write_text('{"acr": {"blocked_tools": ["shell"]}}')
    if projected:
        (root / "..data").symlink_to("..2026", target_is_directory=True)
        for filename in ("custom.rego", name):
            (root / filename).symlink_to(f"..data/{filename}")
    output = tmp_path / "output"
    with pytest.raises(ValueError, match="Unsupported operator policy data"):
        export_bundle(output, root)
    assert not output.exists()
    with pytest.raises(ValueError, match="Unsupported operator policy data"):
        build_active_runtime_bundle([], extensions=str(root))
    with pytest.raises(ValueError, match="Unsupported operator policy data"):
        operator_identity(root)
    assert (source / name).read_text() == '{"acr": {"blocked_tools": ["shell"]}}'


@pytest.mark.skipif(not OPA, reason="set OPA_BINARY to run real OPA checks")
def test_real_opa_data_backed_deny_cannot_silently_become_allow(tmp_path):
    root = tmp_path / "legacy"
    root.mkdir()
    for name, contents in core_sources().items():
        (root / name).write_bytes(contents)
    (root / "custom.rego").write_text(
        "package acr\nimport future.keywords.in\nimport future.keywords.contains\n"
        "import future.keywords.if\n"
        'deny contains "operator blocklist" if { input.action.tool_name in data.acr.blocked_tools }'
    )
    (root / "data.json").write_text('{"acr": {"blocked_tools": ["shell"]}}')
    request = {
        "agent": {"allowed_tools": ["shell"], "forbidden_tools": [], "boundaries": {}},
        "action": {"tool_name": "shell", "parameters": {}},
        "context": {},
    }
    input_path = tmp_path / "input.json"
    input_path.write_text(json.dumps(request))
    process = subprocess.run(
        [OPA, "eval", "-d", str(root), "-i", str(input_path), "--format=json", "data.acr"],
        text=True,
        capture_output=True,
        check=True,
    )
    value = json.loads(process.stdout)["result"][0]["expressions"][0]["value"]
    assert "operator blocklist" in value["deny"]
    assert value["allow"] is False
    # The managed path refuses the entire input, rather than dropping data.json
    # and exporting an apparently compatible bundle that authorizes the action.
    with pytest.raises(ValueError, match="Unsupported operator policy data"):
        export_bundle(tmp_path / "managed", root)
    with pytest.raises(ValueError, match="Unsupported operator policy data"):
        build_active_runtime_bundle([], extensions=str(root))
    assert not (tmp_path / "managed").exists()


async def test_added_data_file_blocks_decisions_from_previously_loaded_bundle(
    tmp_path, monkeypatch
):
    from acr.config import settings

    (tmp_path / "custom.rego").write_text('package acr\ndeny contains "block" if { false }')
    loaded_identity = operator_identity(tmp_path)
    (tmp_path / "data.json").write_text('{"acr": {"blocked_tools": ["shell"]}}')
    monkeypatch.setattr(settings, "policy_extension_dir", str(tmp_path))
    result = {"allow": True, "core_identity": core_identity(), "operator_identity": loaded_identity}
    with (
        patch(
            "acr.pillar2_policy.engine.opa_breaker.call_async",
            new=AsyncMock(return_value={"result": result}),
        ),
        pytest.raises(PolicyEngineError, match="Invalid operator policy configuration"),
    ):
        await evaluate_policy({}, {}, {})


def test_operator_directory_symlink_refused_instead_of_silently_skipped(tmp_path):
    root = tmp_path / "extensions"
    backing = root / "real"
    backing.mkdir(parents=True)
    (backing / "custom.rego").write_text('package acr\ndeny contains "block" if { true }')
    (root / "linked").symlink_to("real", target_is_directory=True)
    with pytest.raises(ValueError, match="directory symlink"):
        extension_files(root)


@pytest.mark.parametrize("projected", [False, True])
def test_test_suffix_operator_policy_refused_without_output(tmp_path, projected):
    root = tmp_path / "operator"
    root.mkdir()
    backing = root / "..2026" if projected else root
    backing.mkdir(exist_ok=True)
    filename = "customer_override_test.rego"
    contents = 'package acr\nimport future.keywords.contains\nimport future.keywords.if\ndeny contains "operator safeguard" if { true }'
    (backing / filename).write_text(contents)
    if projected:
        (root / "..data").symlink_to("..2026", target_is_directory=True)
        (root / filename).symlink_to(f"..data/{filename}")
    with pytest.raises(ValueError, match="test-suffix"):
        export_bundle(tmp_path / "output", root)
    with pytest.raises(ValueError, match="test-suffix"):
        build_active_runtime_bundle([], extensions=str(root))
    with pytest.raises(ValueError, match="test-suffix"):
        operator_identity(root)
    assert not (tmp_path / "output").exists()
    assert (backing / filename).read_text() == contents


@pytest.mark.skipif(not OPA, reason="set OPA_BINARY to run real OPA checks")
def test_real_opa_test_suffix_runtime_deny_cannot_silently_become_allow(tmp_path):
    root = tmp_path / "legacy"
    root.mkdir()
    for name, contents in core_sources().items():
        (root / name).write_bytes(contents)
    (root / "customer_override_test.rego").write_text(
        "package acr\nimport future.keywords.contains\nimport future.keywords.if\n"
        'deny contains "operator safeguard" if { input.action.tool_name == "shell" }'
    )
    input_path = tmp_path / "input.json"
    input_path.write_text(
        json.dumps(
            {
                "agent": {"allowed_tools": ["shell"], "forbidden_tools": [], "boundaries": {}},
                "action": {"tool_name": "shell", "parameters": {}},
                "context": {},
            }
        )
    )
    process = subprocess.run(
        [OPA, "eval", "-d", str(root), "-i", str(input_path), "--format=json", "data.acr"],
        text=True,
        capture_output=True,
        check=True,
    )
    value = json.loads(process.stdout)["result"][0]["expressions"][0]["value"]
    assert "operator safeguard" in value["deny"]
    assert value["allow"] is False
    with pytest.raises(ValueError, match="test-suffix"):
        export_bundle(tmp_path / "managed", root)
    with pytest.raises(ValueError, match="test-suffix"):
        build_active_runtime_bundle([], extensions=str(root))
    assert not (tmp_path / "managed").exists()


async def test_test_suffix_policy_blocks_previously_loaded_decisions(tmp_path, monkeypatch):
    from acr.config import settings

    loaded_identity = operator_identity(tmp_path)
    (tmp_path / "customer_override_test.rego").write_text(
        'package acr\ndeny contains "operator safeguard" if { true }'
    )
    monkeypatch.setattr(settings, "policy_extension_dir", str(tmp_path))
    result = {"allow": True, "core_identity": core_identity(), "operator_identity": loaded_identity}
    with (
        patch(
            "acr.pillar2_policy.engine.opa_breaker.call_async",
            new=AsyncMock(return_value={"result": result}),
        ),
        pytest.raises(PolicyEngineError, match="Invalid operator policy configuration"),
    ):
        await evaluate_policy({}, {}, {})


@pytest.mark.parametrize("hidden", ["..custom.rego", "..custom/deny.rego", "..old/deny.rego"])
def test_projection_refuses_unknown_hidden_policy_entries(tmp_path, hidden):
    backing = tmp_path / "..2026"
    backing.mkdir()
    (backing / "custom.rego").write_text('package acr\ndeny contains "known" if { false }')
    (tmp_path / "..data").symlink_to("..2026", target_is_directory=True)
    (tmp_path / "custom.rego").symlink_to("..data/custom.rego")
    hidden_path = tmp_path / hidden
    hidden_path.parent.mkdir(exist_ok=True)
    hidden_path.write_text('package acr\ndeny contains "hidden safeguard" if { true }')
    with pytest.raises(ValueError, match="Unrecognized hidden"):
        extension_files(tmp_path)


def test_projection_refuses_unmapped_backing_policy(tmp_path):
    backing = tmp_path / "..2026"
    backing.mkdir()
    (backing / "hidden.rego").write_text(
        'package acr\ndeny contains "hidden safeguard" if { true }'
    )
    (tmp_path / "..data").symlink_to("..2026", target_is_directory=True)
    with pytest.raises(ValueError, match="Unmapped Kubernetes"):
        extension_files(tmp_path)
