from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime
from types import SimpleNamespace

from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from acr.common.errors import PolicyReleaseNotFoundError, PolicyValidationError
from acr.config import settings
from acr.db.models import PolicyDraftRecord, PolicyReleaseRecord
from acr.policy_studio.bundles import build_policy_bundle
from acr.policy_studio.distribution import build_active_runtime_bundle
from acr.policy_studio.isolation import validate_studio_policy
from acr.policy_studio.models import PolicyValidationResponse
from acr.policy_studio.publisher import publish_active_policy_bundle, publish_policy_bundle


def validate_policy_draft_record(record: PolicyDraftRecord) -> PolicyValidationResponse:
    issues: list[str] = []
    warnings: list[str] = []
    manifest = record.manifest or {}
    wizard = record.wizard_inputs or {}

    if not manifest.get("agent_id"):
        issues.append("Manifest is missing agent_id")
    if not manifest.get("purpose"):
        issues.append("Manifest is missing purpose")
    if not isinstance(manifest.get("allowed_tools"), list) or not manifest.get("allowed_tools"):
        issues.append("Manifest must include at least one allowed tool")
    if not record.rego_policy.strip():
        issues.append("Rego policy cannot be empty")
    try:
        validate_studio_policy(record.rego_policy, name=record.agent_id)
    except ValueError as exc:
        issues.append(str(exc))
    if wizard.get("escalate_tool") and "escalate" not in record.rego_policy:
        warnings.append(
            "Wizard defines an escalation tool but generated policy does not include an escalate rule"
        )
    if manifest.get("risk_tier") == "high":
        warnings.append("High-risk agent: require approval before enabling in production")

    if not issues:
        candidate = SimpleNamespace(
            agent_id=record.agent_id,
            release_id="candidate",
            version=0,
            activated_at=None,
            rego_policy=record.rego_policy,
        )
        try:
            build_active_runtime_bundle(
                [candidate], extensions=settings.policy_extension_dir or None
            )
        except ValueError as exc:
            issues.append(str(exc))
    return PolicyValidationResponse(valid=not issues, issues=issues, warnings=warnings)


async def list_policy_releases(db: AsyncSession) -> list[PolicyReleaseRecord]:
    result = await db.execute(
        select(PolicyReleaseRecord).order_by(desc(PolicyReleaseRecord.created_at))
    )
    return list(result.scalars().all())


async def list_active_policy_releases(db: AsyncSession) -> list[PolicyReleaseRecord]:
    result = await db.execute(
        select(PolicyReleaseRecord)
        .where(PolicyReleaseRecord.activation_status == "active")
        .order_by(PolicyReleaseRecord.agent_id, desc(PolicyReleaseRecord.version))
    )
    return list(result.scalars().all())


async def get_policy_release(db: AsyncSession, release_id: str) -> PolicyReleaseRecord:
    result = await db.execute(
        select(PolicyReleaseRecord).where(PolicyReleaseRecord.release_id == release_id)
    )
    record = result.scalar_one_or_none()
    if record is None:
        raise PolicyReleaseNotFoundError(f"Policy release '{release_id}' not found")
    return record


async def _validate_candidate(
    db: AsyncSession, record: PolicyDraftRecord | PolicyReleaseRecord
) -> None:
    active = await list_active_policy_releases(db)
    candidate = SimpleNamespace(
        agent_id=record.agent_id,
        release_id="candidate",
        version=0,
        activated_at=None,
        rego_policy=record.rego_policy,
    )
    records = [item for item in active if item.agent_id != record.agent_id] + [candidate]
    try:
        await asyncio.to_thread(
            build_active_runtime_bundle, records, extensions=settings.policy_extension_dir or None
        )
    except ValueError as exc:
        raise PolicyValidationError(str(exc)) from exc


async def activate_policy_release(
    db: AsyncSession,
    *,
    release_id: str,
    actor: str,
) -> PolicyReleaseRecord:
    record = await get_policy_release(db, release_id)
    try:
        validate_studio_policy(record.rego_policy, name=record.agent_id)
    except ValueError as exc:
        raise PolicyValidationError(str(exc)) from exc

    await _validate_candidate(db, record)
    active_result = await db.execute(
        select(PolicyReleaseRecord).where(
            PolicyReleaseRecord.agent_id == record.agent_id,
            PolicyReleaseRecord.activation_status == "active",
        )
    )
    active_releases = active_result.scalars().all()

    artifact = build_policy_bundle(
        release_id=record.release_id,
        agent_id=record.agent_id,
        version=record.version,
        manifest=record.manifest,
        rego_policy=record.rego_policy,
    )
    published = publish_active_policy_bundle(
        agent_id=record.agent_id,
        artifact=artifact,
    )

    for active in active_releases:
        active.activation_status = "inactive"
        active.active_bundle_uri = None
        active.activated_by = None
        active.activated_at = None

    record.activation_status = "active"
    record.active_bundle_uri = published.uri
    record.activated_by = actor
    record.activated_at = datetime.now(UTC)

    await db.flush()
    await db.refresh(record)
    return record


async def publish_policy_draft(
    db: AsyncSession,
    *,
    draft: PolicyDraftRecord,
    actor: str,
    notes: str | None = None,
    rollback_from_release_id: str | None = None,
) -> PolicyReleaseRecord:
    validation = await asyncio.to_thread(validate_policy_draft_record, draft)
    if not validation.valid:
        raise PolicyValidationError("; ".join(validation.issues))

    await _validate_candidate(db, draft)
    version_result = await db.execute(
        select(func.max(PolicyReleaseRecord.version)).where(
            PolicyReleaseRecord.agent_id == draft.agent_id
        )
    )
    current_version = version_result.scalar_one_or_none() or 0

    active_result = await db.execute(
        select(PolicyReleaseRecord).where(
            PolicyReleaseRecord.agent_id == draft.agent_id,
            PolicyReleaseRecord.status == "published",
        )
    )
    active_releases = active_result.scalars().all()

    record = PolicyReleaseRecord(
        release_id=f"prl-{uuid.uuid4()}",
        draft_id=draft.draft_id,
        agent_id=draft.agent_id,
        version=current_version + 1,
        name=draft.name,
        template=draft.template,
        manifest=draft.manifest,
        rego_policy=draft.rego_policy,
        status="published",
        activation_status="inactive",
        published_by=actor,
        rollback_from_release_id=rollback_from_release_id,
        notes=notes,
    )
    db.add(record)
    await db.flush()
    artifact = build_policy_bundle(
        release_id=record.release_id,
        agent_id=record.agent_id,
        version=record.version,
        manifest=record.manifest,
        rego_policy=record.rego_policy,
    )
    published = publish_policy_bundle(
        agent_id=record.agent_id,
        version=record.version,
        artifact=artifact,
    )
    record.artifact_uri = published.uri
    record.artifact_sha256 = published.sha256
    record.publish_backend = published.backend
    for active in active_releases:
        active.status = "superseded"
    await db.flush()
    await db.refresh(record)
    return record


async def rollback_policy_release(
    db: AsyncSession,
    *,
    release_id: str,
    actor: str,
    notes: str | None = None,
) -> PolicyReleaseRecord:
    source = await get_policy_release(db, release_id)
    draft = PolicyDraftRecord(
        draft_id=source.draft_id,
        name=source.name,
        agent_id=source.agent_id,
        template=source.template,
        manifest=source.manifest,
        rego_policy=source.rego_policy,
        wizard_inputs={},
    )
    replacement = await publish_policy_draft(
        db,
        draft=draft,
        actor=actor,
        notes=notes or f"Rollback to {release_id}",
        rollback_from_release_id=release_id,
    )
    source.status = "rolled_back"
    return replacement
