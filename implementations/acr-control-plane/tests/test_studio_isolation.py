"""Real OPA acceptance checks for Studio namespace isolation and Rego dialects."""

from __future__ import annotations

import hashlib
import io
import json
import os
import shutil
import subprocess
import tarfile
from types import SimpleNamespace

import pytest

from acr.policy_studio.core_bundle import core_identity, export_bundle
from acr.policy_studio.distribution import build_active_runtime_bundle
from acr.policy_studio.isolation import isolate_studio_policy, validate_studio_policy

OPA = os.environ.get("OPA_BINARY") or shutil.which("opa")


def release(agent, source):
    return SimpleNamespace(
        agent_id=agent, release_id=agent, version=1, activated_at=None, rego_policy=source
    )


def evaluate(tmp_path, bundle, agent, parameters=None):
    archive = tmp_path / "bundle.tar.gz"
    archive.write_bytes(bundle)
    request = tmp_path / "input.json"
    request.write_text(
        json.dumps(
            {
                "agent": {
                    "agent_id": agent,
                    "allowed_tools": ["query"],
                    "forbidden_tools": [],
                    "boundaries": {"max_actions_per_minute": 100, "max_cost_per_hour_usd": 10},
                },
                "action": {"tool_name": "query", "parameters": parameters or {}},
                "context": {},
            }
        )
    )
    process = subprocess.run(
        [OPA, "eval", "-b", str(archive), "-i", str(request), "--format=json", "data.acr"],
        capture_output=True,
        text=True,
        check=True,
    )
    return json.loads(process.stdout)["result"][0]["expressions"][0]["value"]


@pytest.mark.skipif(not OPA, reason="set OPA_BINARY to run real OPA checks")
@pytest.mark.parametrize("style", ["v0-single", "v0-multiline", "future-single", "v1-multiline"])
def test_all_studio_outputs_and_helpers_are_agent_isolated(tmp_path, style):
    imports = (
        ""
        if style.startswith("v0")
        else (
            "import rego.v1\n"
            if style.startswith("v1")
            else "import future.keywords.if\nimport future.keywords.contains\n"
        )
    )
    condition = " if " if imports else " "
    body = "{ trigger }" if style.endswith("single") else "{\n    trigger\n}"
    deny_head = 'deny contains "A deny"' if imports else 'deny["A deny"]'
    helper = (
        'trigger if { input.action.tool_name == "query" }'
        if imports
        else 'trigger { input.action.tool_name == "query" }'
    )
    source = (
        "# leading comment mentioning package acr and data\npackage\n acr\n"
        + imports
        + helper
        + '\nconstant := "A"\n'
        + "label(x) := x\n"
        + deny_head
        + condition
        + body
        + "\n"
        + "modify"
        + condition
        + body
        + "\n"
        + "escalate"
        + condition
        + body
        + "\n"
        + 'modified_parameters := {"owner": label(constant), "literal": "data.acr"}'
        + condition
        + body
        + "\n"
        + 'modified_action := {"tool_name": "safe", "parameters": {}}'
        + condition
        + body
        + "\n"
        + 'escalate_queue := "A-queue"'
        + condition
        + body
        + "\n"
        + "escalate_sla_minutes := 15"
        + condition
        + body
        + "\n"
    )
    # Same helper/function/constant/default names in another active module must not collide.
    other = (
        'package acr\n default trigger = false\n constant := "B"\n label(x) := "B"\n'
        'deny["B deny"] { trigger }\n default modify = false\n default escalate = false\n'
        'choice := "B" { false } else := "fallback"\n'
    )
    first, second = release("A", source), release("B", other)
    bundle = build_active_runtime_bundle([first, second]).bytes_data
    a = evaluate(tmp_path, bundle, "A")
    b = evaluate(tmp_path, bundle, "B")
    assert a["deny"] == ["A deny"]
    assert a["modify"] is True and a["escalate"] is True
    assert a["modified_parameters"]["owner"] == "A"
    assert a["modified_action"]["tool_name"] == "safe"
    assert a["escalate_queue"] == "A-queue" and a["escalate_sla_minutes"] == 15
    assert b["deny"] == [] and b["allow"] is True and b["escalate"] is False
    assert not b.get("modify") and "modified_parameters" not in b and "modified_action" not in b
    assert b["escalate_queue"] == "default" and b["escalate_sla_minutes"] == 240
    assert "acr_studio" not in b and "constant" not in b and "trigger" not in b
    assert first.rego_policy == source and second.rego_policy == other


@pytest.mark.skipif(not OPA, reason="set OPA_BINARY to run real OPA checks")
def test_legacy_v0_operator_policy_loads_and_stays_global(tmp_path):
    extensions = tmp_path / "extensions"
    extensions.mkdir()
    (extensions / "legacy.rego").write_text(
        'package acr\ndeny["Legacy v0"] { input.action.parameters.block == true }\n'
    )
    export_bundle(tmp_path / "exported", extensions)
    static = (tmp_path / "exported/bundle.tar.gz").read_bytes()
    dynamic = build_active_runtime_bundle(
        [release("A", 'package acr\ndeny["A"] { false }')], extensions=str(extensions)
    ).bytes_data
    for bundle in (static, dynamic):
        for agent in ("A", "B"):
            value = evaluate(tmp_path, bundle, agent, {"block": True})
            assert "Legacy v0" in value["deny"] and value["allow"] is False
            assert value["core_identity"] == core_identity()
        with tarfile.open(fileobj=io.BytesIO(bundle)) as archive:
            manifest = json.load(archive.extractfile(".manifest"))
            assert manifest["rego_version"] == 0
            assert manifest["roots"] == ["acr", "acr_studio"]


@pytest.mark.parametrize(
    "source",
    [
        'package acr.other\ndeny["x"] { true }',
        'package acr\nimport data.acr.helper\ndeny["x"] { helper }',
        'package acr\ndeny["x"] { data.acr.helper }',
        'package acr\ndeny["x"] { data["acr"].helper }',
        'package acr\ndeny["x"] { true } with data.acr.helper as true',
    ],
)
def test_unsupported_studio_references_rejected_before_assembly(source):
    with pytest.raises(ValueError):
        validate_studio_policy(source, name="A")
    with pytest.raises(ValueError):
        build_active_runtime_bundle([release("A", source)])


def test_only_package_is_rewritten_not_bodies_comments_or_strings():
    source = '# package acr\npackage acr\nimport future.keywords.if\nx := "package acr data.acr"\nallow if { input.action.tool_name == `data.acr` }\n'
    isolated, bridge = isolate_studio_policy(agent_id="A", source=source)
    assert isolated.endswith(source.split("package acr\n", 2)[-1])
    assert "# package acr\n" in isolated
    assert 'input.agent.agent_id == "A"' in bridge


def test_dispatch_contract_rejects_previous_unscoped_bundle_identity():
    assert core_identity()["contract_version"] == 3


@pytest.mark.skipif(not OPA, reason="set OPA_BINARY to run real OPA checks")
def test_v1_without_import_and_payload_field_names(tmp_path):
    source = (
        'package acr\ndeny contains "payload" if { input.action.parameters.data == "x"; '
        'input.action.parameters["package"] == "y" }\n'
    )
    artifact = build_active_runtime_bundle([release("A", source)])
    with tarfile.open(fileobj=io.BytesIO(artifact.bytes_data)) as archive:
        manifest = json.load(archive.extractfile(".manifest"))
        assert (
            manifest["file_rego_versions"][
                f"bundle/agents/modules/{hashlib.sha256(b'A').hexdigest()}.rego"
            ]
            == 1
        )
    a = evaluate(tmp_path, artifact.bytes_data, "A", {"data": "x", "package": "y"})
    b = evaluate(tmp_path, artifact.bytes_data, "B", {"data": "x", "package": "y"})
    assert a["deny"] == ["payload"] and b["deny"] == []


@pytest.mark.skipif(not OPA, reason="set OPA_BINARY to run real OPA checks")
@pytest.mark.parametrize(
    "output,value",
    [
        ("deny", True),
        ("deny", "no"),
        ("deny", {"reason": "no"}),
        ("deny", [False]),
        ("allow", "true"),
        ("allow", False),
        ("modify", "yes"),
        ("escalate", 1),
    ],
)
def test_invalid_or_restrictive_outputs_cannot_disappear_into_allow(tmp_path, output, value):
    source = f"package acr\n{output} := input.action.parameters.value\n"
    bundle = build_active_runtime_bundle([release("A", source)]).bytes_data
    a = evaluate(tmp_path, bundle, "A", {"value": value})
    b = evaluate(tmp_path, bundle, "B", {"value": value})
    assert a["deny"] and a["allow"] is False
    assert not b["deny"] and b["allow"] is True


@pytest.mark.skipif(not OPA, reason="set OPA_BINARY to run real OPA checks")
@pytest.mark.parametrize(
    "field,value,effect",
    [
        ("modified_parameters", "wrong", "modify"),
        ("modified_action", [], "modify"),
        ("escalate_queue", 7, "escalate"),
        ("escalate_sla_minutes", -1, "escalate"),
        ("escalate_sla_minutes", 0.5, "escalate"),
    ],
)
def test_invalid_metadata_fails_closed_for_own_effect(tmp_path, field, value, effect):
    source = f"package acr\n{effect} := true\n{field} := input.action.parameters.value\n"
    bundle = build_active_runtime_bundle([release("A", source)]).bytes_data
    assert evaluate(tmp_path, bundle, "A", {"value": value})["deny"]
    assert not evaluate(tmp_path, bundle, "B", {"value": value})["deny"]


@pytest.mark.skipif(not OPA, reason="set OPA_BINARY to run real OPA checks")
def test_metadata_without_effect_is_not_exposed_and_allow_cannot_waive_core(tmp_path):
    source = (
        "package acr\nallow := true\nmodify := false\nescalate := false\n"
        'modified_parameters := {"hidden": true}\nescalate_queue := "hidden"\n'
    )
    bundle = build_active_runtime_bundle([release("A", source)]).bytes_data
    value = evaluate(tmp_path, bundle, "A", {"command": "rm -rf /"})
    assert value["deny"] and value["allow"] is False
    assert "modified_parameters" not in value and value["escalate_queue"] == "default"


@pytest.mark.skipif(not OPA, reason="set OPA_BINARY to run real OPA checks")
@pytest.mark.parametrize(
    "ids",
    [
        ["A", "A.bridge"],
        ["A", "A.bridge", "A.bridge.bridge", "A.bridge.bridge.bridge"],
        ["a", "A", "-", "_", ".bridge", "..bridge", "A.rego", "A.B_9-"],
    ],
)
def test_agent_filenames_never_overwrite_other_agents_safeguards(tmp_path, ids):
    records = [
        release(agent, f"package acr\ndeny[{json.dumps('safeguard ' + agent)}] {{ true }}")
        for agent in ids
    ]
    artifact = build_active_runtime_bundle(records)
    assert artifact.bytes_data == build_active_runtime_bundle(list(reversed(records))).bytes_data
    with tarfile.open(fileobj=io.BytesIO(artifact.bytes_data)) as archive:
        agent_files = [name for name in archive.getnames() if name.startswith("bundle/agents/")]
        assert len(agent_files) == len(ids) * 2
        assert len(set(agent_files)) == len(agent_files)
    for agent in ids:
        value = evaluate(tmp_path, artifact.bytes_data, agent)
        assert value["deny"] == ["safeguard " + agent]
        assert value["allow"] is False
        assert value["core_identity"] == core_identity()
    unrelated = evaluate(tmp_path, artifact.bytes_data, "unrelated")
    assert unrelated["deny"] == [] and unrelated["allow"] is True


@pytest.mark.parametrize(
    "paths",
    [
        ("bundle/agents/modules/collision.rego", "bundle/agents/bridges/collision.rego"),
        ("bundle/common.rego", "bundle/agents/bridges/collision.rego"),
        ("bundle/agents/modules/same.rego", "bundle/agents/modules/same.rego"),
    ],
)
def test_payload_collision_is_rejected_explicitly(monkeypatch, paths):
    monkeypatch.setattr("acr.policy_studio.distribution._agent_bundle_paths", lambda agent: paths)
    records = [
        release("A", 'package acr\ndeny["A"] { true }'),
        release("A.bridge", 'package acr\ndeny["B"] { false }'),
    ]
    with pytest.raises(ValueError, match="payload collision"):
        build_active_runtime_bundle(records)


async def test_previous_collision_prone_contract_is_rejected_on_decision():
    from unittest.mock import AsyncMock, patch

    from acr.common.errors import PolicyEngineError
    from acr.pillar2_policy.engine import evaluate_policy
    from acr.policy_studio.core_bundle import canonical_json, operator_identity

    previous = {"contract_version": 2, "files": core_identity()["files"]}
    previous["core_id"] = hashlib.sha256(canonical_json(previous)).hexdigest()
    response = {
        "result": {
            "allow": True,
            "core_identity": previous,
            "operator_identity": operator_identity(),
        }
    }
    with (
        patch(
            "acr.pillar2_policy.engine.opa_breaker.call_async", new=AsyncMock(return_value=response)
        ),
        pytest.raises(PolicyEngineError, match="managed core"),
    ):
        await evaluate_policy({}, {}, {})
