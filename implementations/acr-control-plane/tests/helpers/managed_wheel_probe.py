"""Run with an installed wheel, outside the checkout and without PYTHONPATH.

Usage: python /path/to/managed_wheel_probe.py [--opa /path/to/opa]
The installed package and supported OPA 0.70 compiler are required.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from acr.policy_studio.core_bundle import core_identity, core_sources


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--opa")
    args = parser.parse_args()
    if args.opa:
        os.environ["OPA_BINARY"] = args.opa
    assert not os.environ.get("PYTHONPATH"), "Run without checkout imports"
    assert set(core_sources()) == {"common.rego", "content_safety.rego"}
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        for name in ("first", "second"):
            subprocess.run(
                [sys.executable, "-m", "acr.policy_studio.core_bundle", "export", "--output", name],
                cwd=root,
                check=True,
                capture_output=True,
            )
        first = root / "first/bundle.tar.gz"
        assert first.read_bytes() == (root / "second/bundle.tar.gz").read_bytes()
        manifest = json.loads((root / "first/manifest.json").read_text())
        assert manifest["core"] == core_identity()
        if args.opa:
            result = subprocess.run(
                [args.opa, "eval", "-b", str(first), "--format=json", "data.acr.core_identity"],
                cwd=root,
                check=True,
                capture_output=True,
                text=True,
            )
            assert (
                json.loads(result.stdout)["result"][0]["expressions"][0]["value"] == core_identity()
            )
    print("Installed-wheel resources, deterministic export, and optional real OPA: PASS")


if __name__ == "__main__":
    main()
