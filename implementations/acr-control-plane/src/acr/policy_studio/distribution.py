from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass

from acr.db.models import PolicyReleaseRecord
from acr.policy_studio.core_bundle import (
    assemble_bundle,
    core_sources,
    extension_files,
    managed_core_files,
    opa_config,
    validate_extension,
)

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
    return core_sources()[filename]


def _common_policy_bytes() -> bytes:
    return _policy_bytes("common.rego")


def _content_safety_policy_bytes() -> bytes:
    return _policy_bytes("content_safety.rego")


def build_active_runtime_bundle(
    active_releases: list[PolicyReleaseRecord],
    *,
    extensions: str | None = None,
) -> RuntimeBundleArtifact:
    active_releases = sorted(
        active_releases, key=lambda record: (record.agent_id, record.release_id)
    )
    if len({record.agent_id for record in active_releases}) != len(active_releases):
        raise ValueError("Multiple active releases for the same agent")
    payloads = {**managed_core_files(), **extension_files(extensions)}
    payloads["bundle/metadata.json"] = json.dumps(
        {
            "type": "acr-active-runtime-bundle",
            "active_release_count": len(active_releases),
            "active_agents": sorted({record.agent_id for record in active_releases}),
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
        sort_keys=True,
    ).encode()
    for record in active_releases:
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", record.agent_id) or record.agent_id in {".", ".."}:
            raise ValueError("Unsafe agent ID in runtime bundle")
        validate_extension(record.rego_policy, name=record.agent_id)
        payloads[f"bundle/agents/{record.agent_id}.rego"] = _scoped_rego_policy(
            agent_id=record.agent_id,
            rego_policy=record.rego_policy,
        ).encode()
    bytes_data, _ = assemble_bundle(payloads)
    return RuntimeBundleArtifact(
        filename="acr-active-runtime.tar.gz",
        content_type="application/gzip",
        bytes_data=bytes_data,
        sha256=hashlib.sha256(bytes_data).hexdigest(),
    )


def build_opa_discovery_document(*, service_base_url: str) -> dict:
    # A configuration document for operators, NOT the OPA discovery protocol.
    return opa_config(service_base_url)
