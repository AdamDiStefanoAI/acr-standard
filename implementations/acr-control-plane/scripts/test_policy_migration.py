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
