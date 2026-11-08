"""Offline legacy v1.2.1 migration checks, no Docker required."""

import hashlib
import shutil
import tempfile
from pathlib import Path

from migrate_operator_policies import migrate


def digest_tree(root):
    return {
        str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in root.rglob("*")
        if p.is_file()
    }


with tempfile.TemporaryDirectory() as temp:
    root = Path(temp)
    source = root / "legacy"
    shutil.copytree("policies/acr", source)
    (source / "custom.rego").write_text("package acr\n# operator custom policy\n")
    before = digest_tree(source)
    destination = root / "operator"
    migrate(source, destination)
    assert digest_tree(source) == before
    assert (destination / "customer_support.rego").read_bytes() == (
        source / "customer_support.rego"
    ).read_bytes()
    assert (destination / "custom.rego").read_bytes() == (source / "custom.rego").read_bytes()
    assert not (destination / "common.rego").exists()
    assert not (destination / "content_safety_test.rego").exists()
    migrate(source, destination)
    (destination / "custom.rego").write_text("keep operator destination")
    try:
        migrate(source, destination)
        raise AssertionError("Overwrote custom policy")
    except SystemExit:
        pass
    assert (destination / "custom.rego").read_text() == "keep operator destination"
    (source / "common.rego").write_text(
        (source / "common.rego").read_text() + "\n# local modification\n"
    )
    try:
        migrate(source, root / "refused")
        raise AssertionError("Silently dropped modified core")
    except SystemExit:
        pass
    assert not (root / "refused").exists()
print("PASS: v1.2.1 migration, preservation, repeatability, no overwrite, modified-core refusal")

# A data-backed deny must not become an apparently successful partial migration.
for name in ("data.json", "data.yaml", "data.yml", "policies.tar.gz", ".manifest", "README.md"):
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        source = root / "legacy"
        source.mkdir()
        (source / "custom.rego").write_text(
            "package acr\nimport future.keywords.if\nimport future.keywords.contains\n"
            'deny contains "data-backed deny" if { data.acr.blocked == true }\n'
        )
        (source / name).write_text('{"acr":{"blocked":true}}')
        before = digest_tree(source)
        destination = root / "operator"
        destination.mkdir()
        (destination / "existing.rego").write_text("package acr\n# existing operator file\n")
        retained = digest_tree(destination)
        try:
            migrate(source, destination)
            raise AssertionError("Silently omitted a data-backed deny dependency: " + name)
        except SystemExit as error:
            assert "nothing copied" in str(error)
            assert "reviewed conversion" in str(error)
        assert digest_tree(source) == before
        assert digest_tree(destination) == retained
        assert not (destination / "custom.rego").exists()
print("PASS: unsupported data/bundle inputs refuse before any copies; source/destination unchanged")

# Test suffixes are only a naming convention, not proof that a module is inert.
for name in ("customer_override_test.rego", "content_safety_test.rego"):
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        source = root / "legacy"
        source.mkdir()
        (source / "aaa_custom.rego").write_text("package acr\n# copy candidate before refusal\n")
        (source / name).write_text(
            "package acr\nimport future.keywords.if\nimport future.keywords.contains\n"
            'deny contains "critical runtime restriction" if { true }\n'
        )
        before = digest_tree(source)
        destination = root / "operator"
        destination.mkdir()
        (destination / "existing.rego").write_text("package acr\n# preserve existing\n")
        retained = digest_tree(destination)
        try:
            migrate(source, destination)
            raise AssertionError("Silently dropped runtime rule with test suffix")
        except SystemExit as error:
            assert "nothing copied" in str(error)
            assert "rename" in str(error)
        assert digest_tree(source) == before
        assert digest_tree(destination) == retained
        assert not (destination / "aaa_custom.rego").exists()
print(
    "PASS: unknown/modified test-suffix rules refuse atomically; only verified stock test is omitted"
)
