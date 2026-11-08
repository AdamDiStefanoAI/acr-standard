#!/usr/bin/env python3
"""Run the two-agent fixture using OPA 0.70 installed on the trusted validation PATH."""

from __future__ import annotations

import argparse
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from types import SimpleNamespace

from managed_policy_validation import STUDIO_POLICY_A, STUDIO_POLICY_B, direct_opa_probe
from migrate_operator_policies import migrate

from acr.policy_studio.distribution import build_active_runtime_bundle


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="acr-two-agent-opa-") as temp:
        root = Path(temp)
        extensions = root / "operator"
        legacy = root / "legacy"
        legacy.mkdir()
        # This must remain valid legacy syntax without future-keyword imports.
        (legacy / "legacy_v0.rego").write_text(
            'package acr\ndeny["Legacy v0 sentinel"] { input.action.parameters.legacy_v0_sentinel == true }\n'
        )
        migrate(legacy, extensions)
        assert (extensions / "legacy_v0.rego").read_bytes() == (
            legacy / "legacy_v0.rego"
        ).read_bytes()
        releases = [
            SimpleNamespace(
                agent_id=agent,
                release_id="fixture-" + agent,
                version=1,
                activated_at=None,
                rego_policy=policy,
            )
            for agent, policy in [
                ("upgrade-ci", STUDIO_POLICY_A),
                ("upgrade-ci-b", STUDIO_POLICY_B),
            ]
        ]
        artifact = build_active_runtime_bundle(releases, extensions=str(extensions))
        archive = root / "bundle.tar.gz"
        archive.write_bytes(artifact.bytes_data)
        subprocess.run(["opa", "check", "--bundle", str(archive)], check=True)
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        url = f"http://127.0.0.1:{port}"
        with (root / "opa.log").open("w+") as log:
            process = subprocess.Popen(
                ["opa", "run", "--server", f"--addr=127.0.0.1:{port}", "--bundle", str(archive)],
                stdout=log,
                stderr=subprocess.STDOUT,
            )
            try:
                for _ in range(100):
                    if process.poll() is not None:
                        log.seek(0)
                        raise AssertionError("OPA exited: " + log.read())
                    try:
                        with urllib.request.urlopen(url + "/health?bundles", timeout=1) as response:
                            if response.status == 200:
                                break
                    except (OSError, urllib.error.URLError):
                        time.sleep(0.1)
                else:
                    raise AssertionError("OPA startup timeout")
                subprocess.run(
                    [sys.executable, "-c", direct_opa_probe()],
                    env={**os.environ, "OPA_URL": url},
                    check=True,
                )
                print("PASS: real OPA legacy v0 deny and two-agent DENY/MODIFY/ESCALATE isolation")
            finally:
                process.terminate()
                process.wait(timeout=10)


if __name__ == "__main__":
    main()
