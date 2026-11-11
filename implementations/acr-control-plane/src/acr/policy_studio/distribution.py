from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass

from acr.db.models import PolicyReleaseRecord
from acr.policy_studio.core_bundle import (
    assemble_bundle,
    canonical_json,
    core_identity,
    core_sources,
    extension_files,
    managed_core_files,
    opa_config,
    operator_identity,
)
from acr.policy_studio.isolation import isolate_studio_policy


@dataclass(frozen=True)
class RuntimeBundleArtifact:
    filename: str
    content_type: str
    bytes_data: bytes
    sha256: str


def _policy_bytes(filename: str) -> bytes:
    return core_sources()[filename]


def _common_policy_bytes() -> bytes:
    return _policy_bytes("common.rego")


def _content_safety_policy_bytes() -> bytes:
    return _policy_bytes("content_safety.rego")


def _agent_bundle_paths(agent_id: str) -> tuple[str, str]:
    key = hashlib.sha256(agent_id.encode()).hexdigest()
    return f"bundle/agents/modules/{key}.rego", f"bundle/agents/bridges/{key}.rego"


def _add_payload(payloads: dict[str, bytes], name: str, payload: bytes) -> None:
    if name in payloads:
        raise ValueError(f"Runtime bundle payload collision at {name}")
    payloads[name] = payload


def studio_release_identity(active_releases: list[PolicyReleaseRecord]) -> str:
    """Content/version identity, independent of compiler and activation timestamps."""
    if len({record.agent_id for record in active_releases}) != len(active_releases):
        raise ValueError("Multiple active releases for the same agent")
    releases = [
        {
            "agent_id": record.agent_id,
            "release_id": record.release_id,
            "version": record.version,
            "rego_sha256": hashlib.sha256(record.rego_policy.encode()).hexdigest(),
        }
        for record in sorted(active_releases, key=lambda item: (item.agent_id, item.release_id))
    ]
    return hashlib.sha256(canonical_json(releases)).hexdigest()


async def expected_policy_identity(db) -> dict:
    """Current configured identity; compare against the exact OPA evaluation result.

    This detects an active-release change before OPA's next bundle poll. It is
    not remote attestation and does not make activation across replicas atomic.
    """
    from acr.config import settings
    from acr.policy_studio.releases import list_active_policy_releases

    return {
        "core": core_identity(),
        "operator": operator_identity(settings.policy_extension_dir or None),
        "studio": studio_release_identity(await list_active_policy_releases(db)),
    }


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
        isolated, bridge = isolate_studio_policy(
            agent_id=record.agent_id,
            source=record.rego_policy,
        )
        module_path, bridge_path = _agent_bundle_paths(record.agent_id)
        _add_payload(payloads, module_path, isolated.encode())
        _add_payload(payloads, bridge_path, bridge.encode())
    bytes_data, _ = assemble_bundle(
        payloads, studio_identity=studio_release_identity(active_releases)
    )
    return RuntimeBundleArtifact(
        filename="acr-active-runtime.tar.gz",
        content_type="application/gzip",
        bytes_data=bytes_data,
        sha256=hashlib.sha256(bytes_data).hexdigest(),
    )


def build_opa_discovery_document(*, service_base_url: str) -> dict:
    # A configuration document for operators, NOT the OPA discovery protocol.
    return opa_config(service_base_url)


async def preflight_active_runtime(*, extensions: str | None = None) -> dict:
    """Read and compile the candidate aggregate without changing DB or artifacts."""
    import asyncio

    from sqlalchemy import select

    from acr.config import settings
    from acr.db.database import async_session_factory
    from acr.policy_studio.core_bundle import core_identity

    async with async_session_factory() as session:
        result = await session.execute(
            select(PolicyReleaseRecord).where(PolicyReleaseRecord.activation_status == "active")
        )
        records = list(result.scalars().all())
        artifact = await asyncio.to_thread(
            build_active_runtime_bundle,
            records,
            extensions=extensions
            if extensions is not None
            else settings.policy_extension_dir or None,
        )
    return {
        "status": "valid",
        "active_release_count": len(records),
        "core_id": core_identity()["core_id"],
        "bundle_sha256": artifact.sha256,
    }


def main() -> None:
    import argparse
    import asyncio

    parser = argparse.ArgumentParser(
        description="Validate DB-active Studio and operator policies before cutover"
    )
    parser.add_argument("command", choices=["preflight"])
    parser.add_argument("--extensions")
    args = parser.parse_args()
    try:
        report = asyncio.run(preflight_active_runtime(extensions=args.extensions))
    except Exception as exc:
        parser.error(f"Active runtime preflight failed: {exc}")
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
