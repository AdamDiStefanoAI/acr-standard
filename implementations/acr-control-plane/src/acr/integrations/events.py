"""Producer-side integration events (v1.5.0 WS4).

Called by the approval, containment, killswitch, and decision paths.
Every function is gated on the integration's enable flag and delegates
to outbox.enqueue_event, which is savepoint-guarded and failure-proof:
these helpers can be awaited from any path without any chance of
changing that path's behavior. With every integration off, none of
these functions writes a row or makes a call.

Chat payloads deliberately exclude approval parameters: a chat channel
is a notification surface, not a data surface. The approvals API (and
its evidence record) carries the parameters; the message carries the
summary an approver needs to find the request.
"""

from __future__ import annotations

import uuid

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from acr.common.time import utcnow
from acr.config import settings
from acr.db.models import PolicyDecisionRecord
from acr.integrations.outbox import enqueue_event
from acr.integrations.sentinel import decision_record

logger = structlog.get_logger(__name__)


def _approval_snapshot(record) -> dict:
    return {
        "request_id": record.request_id,
        "correlation_id": record.correlation_id,
        "agent_id": record.agent_id,
        "tool_name": record.tool_name,
        "description": record.description,
        "approval_queue": record.approval_queue,
        "risk_tier": record.risk_tier,
        "expires_at": record.expires_at.isoformat() if record.expires_at else None,
    }


async def notify_approval_requested(db: AsyncSession, record) -> None:
    payload = _approval_snapshot(record)
    if settings.slack_enabled and settings.slack_approvals_channel:
        await enqueue_event(
            db,
            integration="slack",
            event_type="approval_requested",
            reference=record.request_id,
            correlation_id=record.correlation_id,
            target=settings.slack_approvals_channel,
            payload=payload,
        )
    if settings.teams_enabled and settings.teams_webhook_url:
        await enqueue_event(
            db,
            integration="teams",
            event_type="approval_requested",
            reference=record.request_id,
            correlation_id=record.correlation_id,
            target="teams_webhook",
            payload=payload,
        )


async def notify_approval_decided(db: AsyncSession, record) -> None:
    payload = {
        **_approval_snapshot(record),
        "status": record.status,
        "decided_by": record.decided_by,
        "decided_at": record.decided_at.isoformat() if record.decided_at else None,
    }
    if settings.slack_enabled and settings.slack_approvals_channel:
        await enqueue_event(
            db,
            integration="slack",
            event_type="approval_decided",
            reference=record.request_id,
            correlation_id=record.correlation_id,
            target=settings.slack_approvals_channel,
            payload=payload,
        )
    if settings.teams_enabled and settings.teams_webhook_url:
        await enqueue_event(
            db,
            integration="teams",
            event_type="approval_decided",
            reference=record.request_id,
            correlation_id=record.correlation_id,
            target="teams_webhook",
            payload=payload,
        )
    if (
        settings.servicenow_enabled
        and settings.servicenow_incident_on_deny
        and record.status == "denied"
    ):
        await enqueue_event(
            db,
            integration="servicenow",
            event_type="approval_decided",
            reference=record.request_id,
            correlation_id=record.correlation_id,
            target="incident",
            payload={
                "event_type": "approval_denied",
                "title": (f"ACR approval denied: {record.tool_name} for agent {record.agent_id}"),
                "correlation_id": record.correlation_id,
                "agent_id": record.agent_id,
                "tool_name": record.tool_name,
                "request_id": record.request_id,
                "decided_by": record.decided_by,
                "reason": record.decision_reason,
            },
        )


async def notify_containment(
    db: AsyncSession,
    *,
    reference: str,
    agent_id: str,
    action_type: str,
    tier: int | str,
    reason: str,
    correlation_id: str | None,
) -> None:
    payload = {
        "event_type": "containment_action",
        "title": f"Containment: {action_type} applied to {agent_id}",
        "summary": (f"Agent {agent_id} was contained ({action_type}, tier {tier})."),
        "agent_id": agent_id,
        "action_type": action_type,
        "tier": str(tier),
        "reason": reason,
        "correlation_id": correlation_id or "",
    }
    if settings.slack_enabled and (
        settings.slack_alerts_channel or settings.slack_approvals_channel
    ):
        await enqueue_event(
            db,
            integration="slack",
            event_type="containment_action",
            reference=reference,
            correlation_id=correlation_id,
            target=settings.slack_alerts_channel or settings.slack_approvals_channel,
            payload=payload,
        )
    if settings.teams_enabled and settings.teams_webhook_url:
        await enqueue_event(
            db,
            integration="teams",
            event_type="containment_action",
            reference=reference,
            correlation_id=correlation_id,
            target="teams_webhook",
            payload=payload,
        )
    if settings.servicenow_enabled:
        await enqueue_event(
            db,
            integration="servicenow",
            event_type="containment_action",
            reference=reference,
            correlation_id=correlation_id,
            target="incident",
            payload=payload,
        )


async def notify_killswitch(
    db: AsyncSession, *, agent_id: str, reason: str, operator_id: str | None
) -> None:
    reference = f"kill-{uuid.uuid4()}"
    payload = {
        "event_type": "killswitch_activated",
        "title": f"Kill switch activated for {agent_id}",
        "summary": f"The kill switch was activated for agent {agent_id}.",
        "agent_id": agent_id,
        "action_type": "kill",
        "reason": reason,
        "operator_id": operator_id or "",
        "correlation_id": "",
    }
    if settings.slack_enabled and (
        settings.slack_alerts_channel or settings.slack_approvals_channel
    ):
        await enqueue_event(
            db,
            integration="slack",
            event_type="killswitch_activated",
            reference=reference,
            target=settings.slack_alerts_channel or settings.slack_approvals_channel,
            payload=payload,
        )
    if settings.teams_enabled and settings.teams_webhook_url:
        await enqueue_event(
            db,
            integration="teams",
            event_type="killswitch_activated",
            reference=reference,
            target="teams_webhook",
            payload=payload,
        )
    if settings.servicenow_enabled:
        await enqueue_event(
            db,
            integration="servicenow",
            event_type="killswitch_activated",
            reference=reference,
            target="incident",
            payload=payload,
        )


async def enqueue_sentinel_decisions(
    db: AsyncSession, *, correlation_id: str, sequence: int | None
) -> None:
    """Enqueue Sentinel export rows for decisions that were JUST recorded.

    Called by the gateway strictly after the §18 recording commit has
    succeeded, in its own transaction. Any failure here is logged and
    swallowed by the caller pattern (and by enqueue_event itself): the
    export is a copy of the evidence, never part of it.
    """
    if not settings.sentinel_enabled:
        return
    query = select(PolicyDecisionRecord).where(
        PolicyDecisionRecord.correlation_id == correlation_id
    )
    if sequence is not None:
        query = query.where(PolicyDecisionRecord.sequence == sequence)
    result = await db.execute(query)
    for record in result.scalars().all():
        created = record.created_at or utcnow()
        await enqueue_event(
            db,
            integration="sentinel",
            event_type="decision_export",
            reference=str(record.id),
            correlation_id=correlation_id,
            target=settings.sentinel_stream_name,
            payload={
                "record": decision_record(
                    created_at_iso=created.isoformat(),
                    correlation_id=record.correlation_id,
                    agent_id=record.agent_id,
                    policy_id=record.policy_id,
                    tool_name=record.tool_name,
                    decision=record.decision,
                    enforcement_mode=record.enforcement_mode,
                    reason=record.reason,
                    sequence=record.sequence,
                    latency_ms=record.latency_ms,
                )
            },
        )
