#!/usr/bin/env python3
"""Copy legacy operator policies without altering the source or replacing files."""

import argparse
import hashlib
import json
from pathlib import Path

# Reviewed pre-managed core hashes; customized core requires an explicit review.
LEGACY_CORE = json.loads((Path(__file__).with_name("legacy-core-hashes.json")).read_text())


def migrate(source: Path, destination: Path) -> None:
    files = sorted(source.rglob("*.rego"))
    if not source.is_dir():
        raise SystemExit(f"Legacy policy directory does not exist: {source}")
    # Do not silently omit OPA data or opaque bundles: that can turn an existing
    # data-backed deny rule into allow even when the copied Rego is unchanged.
    for path in sorted(source.rglob("*")):
        if path.is_symlink():
            raise SystemExit(f"Legacy symlink requires manual review; nothing copied: {path}")
        if path.is_file() and path.suffix != ".rego" and path.name != ".gitkeep":
            raise SystemExit(
                f"Unsupported legacy policy input {path}; nothing copied. "
                "Data files and bundled policies require reviewed conversion or explicit "
                "managed-bundle support before migration; keep the original deployment."
            )
    copies = []
    for path in files:
        if path.name.endswith("_test.rego"):
            continue
        content = path.read_bytes()
        if path.name in LEGACY_CORE:
            if hashlib.sha256(content).hexdigest() != LEGACY_CORE[path.name]:
                raise SystemExit(f"Customized core requires manual review; nothing copied: {path}")
            continue
        target = destination / path.relative_to(source)
        if target.exists() and target.read_bytes() != content:
            raise SystemExit(f"Refusing to overwrite operator policy: {target}")
        copies.append((target, content))
    for target, content in copies:
        target.parent.mkdir(parents=True, exist_ok=True)
        if not target.exists():
            with target.open("xb") as stream:
                stream.write(content)
    print(f"Preserved {len(copies)} operator policies in {destination}; source untouched.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    migrate(args.source, args.destination)
