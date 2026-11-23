"""Managed policy identity, deterministic delivery, migration, and fail-closed checks."""

from __future__ import annotations

import copy
import hashlib
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
    _expand_symlink_chain,
    _same_file,
    _windows_canonical_form,
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
        assert manifest["roots"] == ["acr", "acr_studio"]
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
        scoped = archive.extractfile(
            f"bundle/agents/bridges/{hashlib.sha256(b'one').hexdigest()}.rego"
        ).read()
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


def _eval_policy_directory(root: Path, input_path: Path, archive_path: Path) -> dict:
    """Evaluate a legacy policy directory's exact bytes with real OPA.

    The directory is packed into a bundle archive and evaluated with -b
    because OPA's directory loader walks the filesystem with platform-native
    path forms and the Windows build rejects directories the Linux build
    accepts (opa eval -d exits 2 on windows-latest for the directories used
    below, while the same bytes evaluate cleanly from an archive). The tar
    transport evaluates identical bytes on every platform — the same pattern
    as the other real-OPA checks in this module — and the document paths of
    loose files are preserved (a root-level data.json still lands at data.*).
    OPA's stderr is included in the assertion so a loader rejection is
    diagnosable from CI output instead of surfacing as a bare exit code.
    """
    with tarfile.open(archive_path, "w:gz") as bundle:
        for candidate in sorted(root.rglob("*")):
            if candidate.is_file():
                payload = candidate.read_bytes()
                info = tarfile.TarInfo(candidate.relative_to(root).as_posix())
                info.size = len(payload)
                bundle.addfile(info, io.BytesIO(payload))
    process = subprocess.run(
        [OPA, "eval", "-b", str(archive_path), "-i", str(input_path), "--format=json", "data.acr"],
        text=True,
        capture_output=True,
        check=False,
    )
    assert process.returncode == 0, (
        f"OPA eval exited {process.returncode}: {process.stderr.strip()[:2000]}"
    )
    return json.loads(process.stdout)["result"][0]["expressions"][0]["value"]


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
    # write_bytes everywhere: write_text would translate newlines and use the
    # locale encoding on Windows, so the bytes OPA evaluates must not depend
    # on the platform the test runs on.
    (root / "custom.rego").write_bytes(
        b"package acr\nimport future.keywords.in\nimport future.keywords.contains\n"
        b"import future.keywords.if\n"
        b'deny contains "operator blocklist" if { input.action.tool_name in data.acr.blocked_tools }'
    )
    (root / "data.json").write_bytes(b'{"acr": {"blocked_tools": ["shell"]}}')
    request = {
        "agent": {"allowed_tools": ["shell"], "forbidden_tools": [], "boundaries": {}},
        "action": {"tool_name": "shell", "parameters": {}},
        "context": {},
    }
    input_path = tmp_path / "input.json"
    input_path.write_bytes(json.dumps(request).encode())
    value = _eval_policy_directory(root, input_path, tmp_path / "legacy.tar.gz")
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
    (root / "customer_override_test.rego").write_bytes(
        b"package acr\nimport future.keywords.contains\nimport future.keywords.if\n"
        b'deny contains "operator safeguard" if { input.action.tool_name == "shell" }'
    )
    input_path = tmp_path / "input.json"
    input_path.write_bytes(
        json.dumps(
            {
                "agent": {"allowed_tools": ["shell"], "forbidden_tools": [], "boundaries": {}},
                "action": {"tool_name": "shell", "parameters": {}},
                "context": {},
            }
        ).encode()
    )
    value = _eval_policy_directory(root, input_path, tmp_path / "legacy.tar.gz")
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


def test_same_file_compares_stat_identity_not_path_strings(tmp_path):
    # The backing-file mapping check must recognize the same file reached
    # directly and through the projection symlink chain on every platform;
    # resolved path strings are not a portable identity (Windows resolve()
    # can return different string forms for one file).
    target = tmp_path / "real.rego"
    target.write_text("package acr\n")
    direct = tmp_path / "alias.rego"
    direct.symlink_to("real.rego")
    other = tmp_path / "other.rego"
    other.write_text("package acr\n")
    assert _same_file(direct, target)
    assert _same_file(target, target)
    assert not _same_file(other, target)
    assert not _same_file(tmp_path / "missing.rego", target)


def test_projection_refuses_backing_that_maps_to_a_different_file(tmp_path):
    backing = tmp_path / "..2026"
    backing.mkdir()
    (backing / "custom.rego").write_text('package acr\ndeny contains "backing" if { true }')
    (tmp_path / "other.rego").write_text('package acr\ndeny contains "other" if { true }')
    (tmp_path / "..data").symlink_to("..2026", target_is_directory=True)
    # The visible entry exists but resolves to a different file than the
    # backing copy, so the backing copy is not a verified duplicate.
    (tmp_path / "custom.rego").symlink_to("other.rego")
    with pytest.raises(ValueError, match="Unmapped Kubernetes"):
        extension_files(tmp_path)


@pytest.mark.parametrize(
    "first,second",
    [
        # Extended-length prefix on one side only (the resolve() divergence
        # seen when one side is reached through the projection symlink chain).
        (r"\\?\C:\x\..2026\f.rego", r"C:\x\..2026\f.rego"),
        (r"\\?\UNC\server\share\..2026\f.rego", r"\\server\share\..2026\f.rego"),
        # Case and separator spellings of one file.
        (r"C:\X\Sub\F.REGO", r"c:\x\sub\f.rego"),
        ("C:/x/..2026/f.rego", r"C:\x\..2026\f.rego"),
        # A real traversal segment collapses identically on both sides.
        (r"\\?\C:\x\..\2026\f.rego", r"C:\2026\f.rego"),
    ],
)
def test_windows_canonical_form_unifies_spellings_of_one_file(first, second):
    assert _windows_canonical_form(first) == _windows_canonical_form(second)


@pytest.mark.parametrize(
    "first,second",
    [
        (r"C:\x\..2026\f.rego", r"C:\x\..2026\g.rego"),
        (r"\\?\C:\x\..2026\f.rego", r"C:\x\other\f.rego"),
        (r"C:\x\..2026\f.rego", r"D:\x\..2026\f.rego"),
    ],
)
def test_windows_canonical_form_keeps_different_files_apart(first, second):
    assert _windows_canonical_form(first) != _windows_canonical_form(second)


def _stat_unavailable(first, second):
    raise OSError("stat identity unavailable (simulated)")


def test_same_file_falls_back_to_canonical_paths_when_stat_fails(tmp_path, monkeypatch):
    # Simulate the Windows failure mode where the stat leg cannot answer:
    # identity must still be decided, by canonical resolved location.
    target = tmp_path / "real.rego"
    target.write_text("package acr\n")
    direct = tmp_path / "alias.rego"
    direct.symlink_to("real.rego")
    other = tmp_path / "other.rego"
    other.write_text("package acr\n")
    monkeypatch.setattr(os.path, "samefile", _stat_unavailable)
    assert _same_file(direct, target)
    assert not _same_file(other, target)
    assert not _same_file(tmp_path / "missing.rego", target)


def test_projection_mapping_survives_stat_failure(tmp_path, monkeypatch):
    # The exact projected layout of the configmap tests, with the stat leg
    # sabotaged: the mapping must still verify via canonical paths, so the
    # backing copy is deduplicated instead of reported unmapped.
    root = tmp_path / "mount"
    backing = root / "..2026"
    backing.mkdir(parents=True)
    (backing / "custom.rego").write_text('package acr\ndeny contains "custom" if { true }')
    (root / "..data").symlink_to("..2026", target_is_directory=True)
    (root / "custom.rego").symlink_to("..data/custom.rego")
    monkeypatch.setattr(os.path, "samefile", _stat_unavailable)
    assert list(extension_files(root)) == ["bundle/extensions/custom.rego"]


def _patch_windows_projection_chain(monkeypatch, *, data_target="..2026"):
    """Simulate the Windows projection chain with a link table.

    Reproduces the environment the round-2 CI run diagnosed: Path.resolve()
    expanded the visible file symlink (mount/custom.rego ->
    mount/..data/custom.rego) but not the intermediate ..data directory
    symlink, and os.path.samefile could not equate the two spellings. The
    fakes give the manual chain expander a two-hop chain to walk (visible
    file -> ..data -> timestamped backing directory); any path outside the
    table behaves as it does on the real filesystem.
    """
    links = {
        "C:/mount/custom.rego": "..data/custom.rego",
        "C:/mount/..data": data_target,
    }
    real_islink = os.path.islink

    def fake_islink(path):
        return str(path) in links or real_islink(path)

    def fake_readlink(path):
        try:
            return links[str(path)]
        except KeyError:
            raise OSError("not a simulated link") from None

    monkeypatch.setattr(os.path, "islink", fake_islink)
    monkeypatch.setattr(os, "readlink", fake_readlink)


def test_expand_symlink_chain_walks_the_windows_projection_chain(monkeypatch):
    _patch_windows_projection_chain(monkeypatch)
    assert _expand_symlink_chain(Path("C:/mount/custom.rego")) == Path(
        "C:/mount/..2026/custom.rego"
    )
    # The backing path itself contains no links and is returned unchanged.
    assert _expand_symlink_chain(Path("C:/mount/..2026/custom.rego")) == Path(
        "C:/mount/..2026/custom.rego"
    )


def test_same_file_expands_the_windows_projection_chain(monkeypatch):
    # With the stat leg sabotaged, identity must come from the manually
    # expanded chain: the visible file's chain terminates exactly at the
    # backing file.
    _patch_windows_projection_chain(monkeypatch)
    monkeypatch.setattr(os.path, "samefile", _stat_unavailable)
    visible = Path("C:/mount/custom.rego")
    backing = Path("C:/mount/..2026/custom.rego")
    assert _same_file(visible, backing)
    assert _same_file(backing, visible)


def test_same_file_rejects_a_chain_terminating_at_a_different_file(monkeypatch):
    # The visible chain terminates in a different backing directory than
    # the file under test, so expansion must not equate them.
    _patch_windows_projection_chain(monkeypatch, data_target="..2027")
    monkeypatch.setattr(os.path, "samefile", _stat_unavailable)
    assert not _same_file(Path("C:/mount/custom.rego"), Path("C:/mount/..2026/custom.rego"))
