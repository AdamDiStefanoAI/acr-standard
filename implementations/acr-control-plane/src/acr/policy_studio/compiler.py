"""Validate candidate bundles with the same OPA compiler used by deployments."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from functools import lru_cache
from pathlib import Path


def _executable() -> tuple[str, int, int]:
    configured = os.environ.get("OPA_BINARY", "opa")
    executable = shutil.which(configured)
    if executable is None:
        raise ValueError(
            "OPA compiler unavailable. Install the supported OPA 0.70 executable on PATH "
            "or set OPA_BINARY before exporting, publishing, or activating policy bundles."
        )
    stat = Path(executable).stat()
    identity = (executable, stat.st_mtime_ns, stat.st_size)
    _check_version(*identity)
    return identity


@lru_cache(maxsize=8)
def _check_version(executable: str, mtime_ns: int, size: int) -> None:
    try:
        result = subprocess.run(
            [executable, "version"], capture_output=True, text=True, timeout=5, check=False
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError(f"Unable to verify OPA compiler version: {exc}") from exc
    if result.returncode or "Version: 0.70.0" not in result.stdout.splitlines():
        raise ValueError("Unsupported OPA compiler version; this release requires OPA 0.70.0")


def validate_bundle(archive: bytes) -> None:
    _compile(archive, *_executable())


def file_rego_version(source: bytes) -> int:
    return _parse_version(source, *_executable())


@lru_cache(maxsize=128)
def _parse_version(source: bytes, executable: str, mtime_ns: int, size: int) -> int:
    with tempfile.TemporaryDirectory(prefix="acr-parse-") as directory:
        policy = Path(directory) / "candidate.rego"
        policy.write_bytes(source)
        for version in (0, 1):
            command = [executable, "parse", str(policy)]
            if version:
                command.append("--v1-compatible")
            try:
                result = subprocess.run(
                    command,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=10,
                    check=False,
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise ValueError(f"OPA policy parsing could not complete: {exc}") from exc
            if result.returncode == 0:
                return version
        raise ValueError(f"OPA rejected candidate policy syntax: {result.stderr.strip()[:2000]}")


@lru_cache(maxsize=32)
def _compile(archive: bytes, executable: str, mtime_ns: int, size: int) -> None:
    # The identity of both the candidate bytes and compiler installation keys the
    # cache. Polling unchanged bundles does not spawn a compiler on every request.
    with tempfile.TemporaryDirectory(prefix="acr-compile-") as directory:
        bundle = Path(directory) / "candidate.tar.gz"
        bundle.write_bytes(archive)
        try:
            result = subprocess.run(
                [executable, "check", "--bundle", str(bundle)],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ValueError(f"OPA candidate compilation could not complete: {exc}") from exc
        if result.returncode:
            detail = (result.stderr or result.stdout).strip()[:2000]
            raise ValueError(f"OPA rejected candidate policy bundle: {detail}")
