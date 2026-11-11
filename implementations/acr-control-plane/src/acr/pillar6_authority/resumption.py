"""Fresh authorization for delayed actions; never treat an approval as a capability."""

from __future__ import annotations

import hashlib
import json
import math
from datetime import UTC

from acr.common.errors import ApprovalConflictError, RuntimeControlDependencyError
from acr.common.redis_client import get_redis_or_none
from acr.common.time import utcnow
from acr.gateway.spend_control import get_authoritative_projected_spend, resolve_action_cost_usd
from acr.pillar1_identity.registry import get_manifest
from acr.pillar1_identity.validator import validate_agent_identity
from acr.pillar2_policy.engine import evaluate_policy
from acr.pillar2_policy.output_filter import filter_parameters
from acr.pillar5_containment.graduated import _ISOLATE_PREFIX, _RESTRICT_PREFIX, _THROTTLE_PREFIX
from acr.pillar5_containment.killswitch import is_agent_killed
from acr.policy_studio.distribution import expected_policy_identity


def digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    ).hexdigest()


def action_payload(record) -> dict:
    return {
        "agent_id": record.agent_id,
        "tool_name": record.tool_name,
        "parameters": record.parameters or {},
        "description": record.description,
        "correlation_id": record.correlation_id,
        "approval_request_id": record.request_id,
    }


def request_digest(record) -> str:
    expiry = record.expires_at
    if expiry is not None:
        expiry = expiry.replace(tzinfo=UTC) if expiry.tzinfo is None else expiry.astimezone(UTC)
    return digest(
        {
            "payload": action_payload(record),
            "queue": record.approval_queue,
            "expires_at": expiry.isoformat() if expiry else None,
            "context": record.request_context or {},
        }
    )


def check_request(record) -> None:
    if record.expires_at is not None:
        expiry = record.expires_at
        if expiry.tzinfo is None:  # SQLite test driver drops timezone; DB contract is UTC.
            expiry = expiry.replace(tzinfo=UTC)
        if expiry <= utcnow():
            raise ApprovalConflictError("Approval expired; submit a new action for approval")
    if not record.request_payload_hash or record.request_payload_hash != request_digest(record):
        raise ApprovalConflictError("Approval payload changed or is unbound; submit a new action")


async def containment(agent_id: str) -> dict:
    if await is_agent_killed(agent_id):
        raise ApprovalConflictError("Agent is killed; approval cannot resume")
    redis = get_redis_or_none()
    if redis is None:
        raise RuntimeControlDependencyError("Approval containment state unavailable")
    values = {}
    for name, prefix in (
        ("isolate", _ISOLATE_PREFIX),
        ("restrict", _RESTRICT_PREFIX),
        ("throttle", _THROTTLE_PREFIX),
    ):
        values[name] = await redis.get(f"{prefix}{agent_id}")
    return values


def authorization_snapshot(manifest, policy_identity: dict, containment_state: dict) -> dict:
    return {
        "manifest_hash": digest(manifest.model_dump(mode="json")),
        "policy_identity": policy_identity,
        "containment": containment_state,
    }


async def revalidate(db, record) -> tuple[dict, float]:
    check_request(record)
    if not record.authorization_snapshot:
        raise ApprovalConflictError("Legacy/unbound approval requires a new action and approval")
    await validate_agent_identity(db, record.agent_id)
    manifest = await get_manifest(db, record.agent_id)
    state = await containment(record.agent_id)
    if state["isolate"] == "1":
        raise ApprovalConflictError("Isolated agent cannot resume execution")
    if state["restrict"] is not None and record.tool_name not in json.loads(state["restrict"]):
        raise ApprovalConflictError("Containment no longer permits this tool")
    identity = await expected_policy_identity(db)
    current = authorization_snapshot(manifest, identity, state)
    if current != record.authorization_snapshot:
        raise ApprovalConflictError("Authorization changed; submit a new action for approval")
    redis = get_redis_or_none()
    # The containment check above requires Redis even in development: delayed
    # high-risk execution has no dependency-bypass mode.
    bucket = utcnow().strftime("%Y%m%d%H%M")
    count = await redis.incr(f"acr:rate:{record.agent_id}:{bucket}")
    await redis.expire(f"acr:rate:{record.agent_id}:{bucket}", 120)
    throttle = int(state["throttle"] or 100)
    if not 0 < throttle <= 100:
        raise ApprovalConflictError("Invalid or fully throttled containment state")
    cost = resolve_action_cost_usd(manifest, record.tool_name)
    context = {
        **(record.request_context or {}),
        "actions_this_minute": math.ceil(count * 100 / throttle),
        "hourly_spend_usd": await get_authoritative_projected_spend(record.agent_id, cost),
    }
    action = {
        "tool_name": record.tool_name,
        "parameters": record.parameters or {},
        "description": record.description,
    }
    result = await evaluate_policy(manifest.model_dump(), action, context)
    if result.policy_identity != identity:
        raise ApprovalConflictError("Evaluator policy is stale or unbound; no execution")
    if result.final_decision not in {"allow", "escalate"}:
        raise ApprovalConflictError("Current policy denies or changes the approved action")
    if result.final_decision == "escalate" and result.approval_queue != record.approval_queue:
        raise ApprovalConflictError("Current policy requires a different approval queue")
    filtered = filter_parameters(record.tool_name, record.parameters or {}, record.correlation_id)
    if filtered.parameters != (record.parameters or {}):
        raise ApprovalConflictError("Output controls changed the payload; reapproval required")
    # Detect policy activation during evaluation, before durable dispatch claim.
    if await expected_policy_identity(db) != identity:
        raise ApprovalConflictError("Policy changed during revalidation; no execution")
    check_request(record)
    return {
        **current,
        "policy_decision": result.final_decision,
        "decided_by": record.decided_by,
        "decision": record.decision,
        "decision_reason": record.decision_reason,
        "decided_at": record.decided_at.isoformat() if record.decided_at else None,
        "validated_at": utcnow().isoformat(),
        "payload_hash": digest(action_payload(record)),
        "approved_payload": action_payload(record),
        "request_context": record.request_context or {},
        "approval_queue": record.approval_queue,
        "expires_at": record.expires_at.isoformat() if record.expires_at else None,
    }, cost


async def check_dispatch_boundary(db, record, snapshot: dict) -> None:
    """Re-read after the durable claim, closing the slow-evaluation/commit window.

    Independent DB/Redis/executor systems cannot form an atomic revocation fence;
    downstream enforcement is still required for revocation concurrent with send.
    """
    from sqlalchemy import select

    from acr.db.models import AgentRecord

    await db.refresh(record)
    check_request(record)
    if record.status not in {"approved", "overridden"}:
        raise ApprovalConflictError("Approval no longer authorizes execution")
    await db.execute(
        select(AgentRecord)
        .where(AgentRecord.agent_id == record.agent_id)
        .execution_options(populate_existing=True)
    )
    await validate_agent_identity(db, record.agent_id)
    manifest = await get_manifest(db, record.agent_id)
    current = authorization_snapshot(
        manifest, await expected_policy_identity(db), await containment(record.agent_id)
    )
    if current != {
        key: snapshot[key] for key in ("manifest_hash", "policy_identity", "containment")
    }:
        raise ApprovalConflictError("Authorization changed before dispatch; reapproval required")
    if digest(action_payload(record)) != snapshot["payload_hash"]:
        raise ApprovalConflictError("Approved payload changed before dispatch")
