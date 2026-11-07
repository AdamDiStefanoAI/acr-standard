from __future__ import annotations

import hashlib
import io
import json
import re
import tarfile
from dataclasses import dataclass
from pathlib import Path

from acr.db.models import PolicyReleaseRecord

_RULE_HEAD_RE = re.compile(r"^\s*[^#\s].*\sif\s\{\s*$")


@dataclass(frozen=True)
class RuntimeBundleArtifact:
    filename: str
    content_type: str
    bytes_data: bytes
    sha256: str


def _scoped_rego_policy(*, agent_id: str, rego_policy: str) -> str:
    guard = f'    input.agent.agent_id == "{agent_id}"'
    scoped_lines: list[str] = []
    for line in rego_policy.splitlines():
        scoped_lines.append(line)
        if _RULE_HEAD_RE.match(line):
            scoped_lines.append(guard)
    return "\n".join(scoped_lines) + "\n"


def _policy_bytes(filename: str) -> bytes:
    current = Path(__file__).resolve()
    for parent in current.parents:
        candidate = parent / "policies" / "acr" / filename
        if candidate.exists():
            return candidate.read_bytes()
    raise FileNotFoundError(
        f"Unable to locate policies/acr/{filename} from policy_studio/distribution.py"
    )


def _common_policy_bytes() -> bytes:
    return _policy_bytes("common.rego")


def _content_safety_policy_bytes() -> bytes:
    return _policy_bytes("content_safety.rego")


def build_active_runtime_bundle(
    active_releases: list[PolicyReleaseRecord],
) -> RuntimeBundleArtifact:
    buffer = io.BytesIO()
    active_agents = sorted({record.agent_id for record in active_releases})

    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        files: dict[str, bytes] = {
            "bundle/common.rego": _common_policy_bytes(),
            "bundle/content_safety.rego": _content_safety_policy_bytes(),
            "bundle/metadata.json": json.dumps(
                {
                    "type": "acr-active-runtime-bundle",
                    "active_release_count": len(active_releases),
                    "active_agents": active_agents,
                    "releases": [
                        {
                            "release_id": record.release_id,
                            "agent_id": record.agent_id,
                            "version": record.version,
                            "activated_at": record.activated_at.isoformat()
                            if record.activated_at
                            else None,
                        }
                        for record in active_releases
                    ],
                },
                indent=2,
            ).encode(),
        }

        for record in active_releases:
            files[f"bundle/agents/{record.agent_id}.rego"] = _scoped_rego_policy(
                agent_id=record.agent_id,
                rego_policy=record.rego_policy,
            ).encode()

        for name, payload in files.items():
            info = tarfile.TarInfo(name=name)
            info.size = len(payload)
            tar.addfile(info, io.BytesIO(payload))

    bytes_data = buffer.getvalue()
    return RuntimeBundleArtifact(
        filename="acr-active-runtime.tar.gz",
        content_type="application/gzip",
        bytes_data=bytes_data,
        sha256=hashlib.sha256(bytes_data).hexdigest(),
    )


def build_opa_discovery_document(*, service_base_url: str) -> dict:
    return {
        "services": {
            "acr_control_plane": {
                "url": service_base_url.rstrip("/"),
            }
        },
        "bundles": {
            "acr_active_runtime": {
                "service": "acr_control_plane",
                "resource": "/acr/policy-bundles/active.tar.gz",
            }
        },
    }
