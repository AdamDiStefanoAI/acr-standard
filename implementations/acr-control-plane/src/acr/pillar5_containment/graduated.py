"""Pillar 5: Graduated response tiers — throttle → restrict → isolate → kill.

Enforcement model
-----------------
Tiers 1–3 write Redis keys that the hot-path (/acr/evaluate) reads on every
request to apply rate-limit throttling, tool restriction, or full isolation.
Tier 4 (KILL) delegates to the independent kill-switch service.

Redis key schema:
  acr:throttle:{agent_id}   → "50"  (percent of normal rate limit)  TTL 3600s
  acr:restrict:{agent_id}   → JSON list of allowed tool names       TTL 3600s
  acr:isolate:{agent_id}    → "1"  (all actions require approval)   TTL 3600s
"""

from __future__ import annotations

import json

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from acr.common.redis_client import get_redis_or_none
from acr.db.models import ContainmentActionRecord
from acr.pillar5_containment.killswitch import kill_agent
from acr.pillar5_containment.models import (
    DRIFT_THRESHOLDS,
    ContainmentAction,
    ContainmentTier,
)

logger = structlog.get_logger(__name__)

# Redis key prefixes for graduated enforcement (read by the hot path)
_THROTTLE_PREFIX = "acr:throttle:"
_RESTRICT_PREFIX = "acr:restrict:"
_ISOLATE_PREFIX = "acr:isolate:"

# TTL for all graduated enforcement keys (1 hour)
_ENFORCEMENT_TTL = 3600


def tier_for_score(drift_score: float) -> ContainmentTier:
    """Return the containment tier appropriate for the given drift score."""
    if drift_score >= DRIFT_THRESHOLDS[ContainmentTier.KILL]:
        return ContainmentTier.KILL
    if drift_score >= DRIFT_THRESHOLDS[ContainmentTier.ISOLATE]:
        return ContainmentTier.ISOLATE
    if drift_score >= DRIFT_THRESHOLDS[ContainmentTier.RESTRICT]:
        return ContainmentTier.RESTRICT
    if drift_score >= DRIFT_THRESHOLDS[ContainmentTier.THROTTLE]:
        return ContainmentTier.THROTTLE
    return ContainmentTier.NONE


async def _enforce_tier_redis(tier: ContainmentTier, agent_id: str) -> None:
    """Write the Redis enforcement key for tiers 1–3.

    The hot path checks these keys to throttle, restrict, or isolate agents.
    """
    redis = get_redis_or_none()
    if redis is None:
        logger.warning("graduated_enforcement_skipped_no_redis", agent_id=agent_id, tier=tier.value)
        return

    try:
        if tier == ContainmentTier.THROTTLE:
            # Reduce the agent's effective rate limit to 50% of normal
            await redis.setex(f"{_THROTTLE_PREFIX}{agent_id}", _ENFORCEMENT_TTL, "50")

        elif tier == ContainmentTier.RESTRICT:
            # Limit agent to an allowed-tool whitelist.  Default to empty list
            # (no tools allowed); operators can update via the console.
            await redis.setex(f"{_RESTRICT_PREFIX}{agent_id}", _ENFORCEMENT_TTL, json.dumps([]))

        elif tier == ContainmentTier.ISOLATE:
            # Block all tool execution — every action requires human approval.
            await redis.setex(f"{_ISOLATE_PREFIX}{agent_id}", _ENFORCEMENT_TTL, "1")

    except Exception as exc:
        logger.error(
            "graduated_enforcement_redis_write_failed",
            agent_id=agent_id,
            tier=tier.value,
            error=str(exc),
        )


async def apply_graduated_response(
    db: AsyncSession,
    agent_id: str,
    drift_score: float,
    correlation_id: str | None = None,
) -> ContainmentAction | None:
    """
    Apply the appropriate containment tier based on drift score.
    Returns the action taken, or None if no action needed.
    """
    tier = tier_for_score(drift_score)
    if tier == ContainmentTier.NONE:
        return None

    action_type = {
        ContainmentTier.THROTTLE: "throttle",
        ContainmentTier.RESTRICT: "restrict",
        ContainmentTier.ISOLATE: "isolate",
        ContainmentTier.KILL: "kill",
    }[tier]

    reason = f"Automated containment: drift_score={drift_score:.3f} triggered Tier {tier.value} ({action_type})"

    logger.warning(
        "graduated_response",
        agent_id=agent_id,
        tier=tier.value,
        action_type=action_type,
        drift_score=drift_score,
        correlation_id=correlation_id,
    )

    # Persist to containment_actions table
    record = ContainmentActionRecord(
        agent_id=agent_id,
        action_type=action_type,
        tier=tier.value,
        reason=reason,
        drift_score=drift_score,
        correlation_id=correlation_id,
    )
    db.add(record)
    await db.flush()

    # Integration alerts (v1.5.0 WS4): enqueue containment alerts /
    # ServiceNow incident via the async outbox. Savepoint-guarded inside
    # enqueue_event — alerting can never affect the containment action.
    from acr.integrations.events import notify_containment

    await notify_containment(
        db,
        reference=str(record.id),
        agent_id=agent_id,
        action_type=action_type,
        tier=tier.value,
        reason=reason,
        correlation_id=correlation_id,
    )

    # Enforce: tiers 1–3 write Redis keys; tier 4 invokes the kill switch.
    if tier == ContainmentTier.KILL:
        await kill_agent(agent_id, reason=reason, operator_id="acr-drift-detector")
        from acr.pillar4_observability.otel import get_meter

        get_meter().create_counter("acr.containment.kills").add(1)
    else:
        await _enforce_tier_redis(tier, agent_id)

    return ContainmentAction(
        agent_id=agent_id,
        tier=tier,
        action_type=action_type,
        reason=reason,
        drift_score=drift_score,
        correlation_id=correlation_id,
    )
