"""Pillar 4: Decision explorer (v1.5.0 WS3).

The read surface an auditor actually uses: filter the decision record,
then open one action and see its full chain — the manifest snapshot as
evaluated, the policy identity that decided, the decision records with
their §18 sequence, the approval and execution receipt where they
exist, and the telemetry events.

Assembled from the real tables. Where a link does not exist for an
action, the chain says so explicitly, per link: a missing approval for
an allowed call is a fact about the action, and silently omitting the
field would make "no approval" indistinguishable from "not looked".
The one link the current schema cannot always produce is the manifest
snapshot as evaluated: it exists only when WS2 evaluation-input
retention was on for the evaluation (the retained payload carries the
exact manifest handed to the policy engine). When it is absent the
chain reports that, and never substitutes the agent's current manifest
as if it were the evaluated one.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

import structlog
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from acr.common.errors import EvidenceBundleNotFoundError
from acr.db.models import (
    AgentRecord,
    ApprovalRequestRecord,
    EvaluationInputRecord,
    ExecutionReceiptRecord,
    PolicyDecisionRecord,
    TelemetryEventRecord,
)

logger = structlog.get_logger(__name__)


class DecisionSummary(BaseModel):
    id: str
    correlation_id: str
    agent_id: str
    policy_id: str
    decision: str
    enforcement_mode: str
    reason: str | None
    tool_name: str | None
    latency_ms: int | None
    sequence: int | None
    created_at: datetime


class DecisionListResponse(BaseModel):
    items: list[DecisionSummary]
    total: int
    limit: int
    offset: int


class ChainLink(BaseModel):
    status: Literal["present", "absent"]
    detail: str


class DecisionChain(BaseModel):
    identifier: str
    correlation_id: str
    agent_id: str
    # The manifest exactly as evaluated, when WS2 retention captured it.
    manifest_snapshot: dict[str, Any] | None
    manifest_link: ChainLink
    retained_input: dict[str, Any] | None
    # What the decision rows themselves record, plus the bundle identity
    # when an approval's authorization snapshot carries one.
    policy_ids: list[str]
    policy_bundle_identifier: dict[str, Any] | None
    policy_link: ChainLink
    decisions: list[DecisionSummary]
    approval: dict[str, Any] | None
    approval_link: ChainLink
    execution_receipt: dict[str, Any] | None
    execution_link: ChainLink
    telemetry_events: list[dict[str, Any]]
    telemetry_link: ChainLink
    missing_links: list[str] = Field(default_factory=list)


def _summary(record: PolicyDecisionRecord) -> DecisionSummary:
    return DecisionSummary(
        id=str(record.id),
        correlation_id=record.correlation_id,
        agent_id=record.agent_id,
        policy_id=record.policy_id,
        decision=record.decision,
        enforcement_mode=record.enforcement_mode,
        reason=record.reason,
        tool_name=record.tool_name,
        latency_ms=record.latency_ms,
        sequence=record.sequence,
        created_at=record.created_at,
    )


async def list_decisions(
    db: AsyncSession,
    *,
    actor: str,
    agent_id: str | None = None,
    window_start: datetime | None = None,
    window_end: datetime | None = None,
    decision: str | None = None,
    enforcement_mode: str | None = None,
    reason_contains: str | None = None,
    tool_name: str | None = None,
    correlation_id: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> DecisionListResponse:
    conditions = []
    if agent_id:
        conditions.append(PolicyDecisionRecord.agent_id == agent_id)
    if window_start:
        conditions.append(PolicyDecisionRecord.created_at >= window_start)
    if window_end:
        conditions.append(PolicyDecisionRecord.created_at <= window_end)
    if decision:
        conditions.append(PolicyDecisionRecord.decision == decision)
    if enforcement_mode:
        conditions.append(PolicyDecisionRecord.enforcement_mode == enforcement_mode)
    if reason_contains:
        conditions.append(PolicyDecisionRecord.reason.ilike(f"%{reason_contains}%"))
    if tool_name:
        conditions.append(PolicyDecisionRecord.tool_name == tool_name)
    if correlation_id:
        conditions.append(PolicyDecisionRecord.correlation_id == correlation_id)

    total = (
        await db.execute(select(func.count()).select_from(PolicyDecisionRecord).where(*conditions))
    ).scalar_one()
    result = await db.execute(
        select(PolicyDecisionRecord)
        .where(*conditions)
        .order_by(PolicyDecisionRecord.created_at.desc(), PolicyDecisionRecord.sequence.desc())
        .limit(limit)
        .offset(offset)
    )
    items = [_summary(record) for record in result.scalars().all()]
    # Every explorer read is itself part of the audit story (WS3 scope):
    # who looked, at what slice, and how much of it there was.
    logger.info(
        "decision_explorer_list_read",
        actor=actor,
        agent_id=agent_id,
        decision=decision,
        enforcement_mode=enforcement_mode,
        tool_name=tool_name,
        correlation_id=correlation_id,
        total=int(total),
        returned=len(items),
    )
    return DecisionListResponse(items=items, total=int(total), limit=limit, offset=offset)


def _approval_dict(record: ApprovalRequestRecord) -> dict[str, Any]:
    return {
        "request_id": record.request_id,
        "correlation_id": record.correlation_id,
        "agent_id": record.agent_id,
        "tool_name": record.tool_name,
        "parameters": record.parameters or {},
        "description": record.description,
        "risk_tier": record.risk_tier,
        "approval_queue": record.approval_queue,
        "status": record.status,
        "decision": record.decision,
        "decided_by": record.decided_by,
        "decision_reason": record.decision_reason,
        "sla_minutes": record.sla_minutes,
        "expires_at": record.expires_at.isoformat() if record.expires_at else None,
        "decided_at": record.decided_at.isoformat() if record.decided_at else None,
        "created_at": record.created_at.isoformat() if record.created_at else None,
        "execution_result": record.execution_result,
        "authorization_snapshot": record.authorization_snapshot,
        "request_payload_hash": record.request_payload_hash,
    }


def _receipt_dict(record: ExecutionReceiptRecord) -> dict[str, Any]:
    return {
        "attempt_id": record.attempt_id,
        "approval_request_id": record.approval_request_id,
        "payload_hash": record.payload_hash,
        "authorization_snapshot": record.authorization_snapshot,
        "state": record.state,
        "result": record.result,
        "error": record.error,
        "created_at": record.created_at.isoformat() if record.created_at else None,
        "completed_at": record.completed_at.isoformat() if record.completed_at else None,
    }


async def get_decision_chain(
    db: AsyncSession,
    *,
    actor: str,
    identifier: str,
) -> DecisionChain:
    """Assemble the full chain for one action.

    `identifier` is a correlation_id, or a single decision row's id —
    both resolve to the action's correlation and its whole chain.
    """
    decisions_result = await db.execute(
        select(PolicyDecisionRecord)
        .where(PolicyDecisionRecord.correlation_id == identifier)
        .order_by(PolicyDecisionRecord.sequence.asc(), PolicyDecisionRecord.created_at.asc())
    )
    decisions = list(decisions_result.scalars().all())
    if not decisions:
        try:
            decision_uuid = uuid.UUID(identifier)
        except ValueError:
            decision_uuid = None
        if decision_uuid is not None:
            row = (
                await db.execute(
                    select(PolicyDecisionRecord).where(PolicyDecisionRecord.id == decision_uuid)
                )
            ).scalar_one_or_none()
            if row is not None:
                return await get_decision_chain(db, actor=actor, identifier=row.correlation_id)
        raise EvidenceBundleNotFoundError(
            f"No policy decisions found for identifier '{identifier}'"
        )

    correlation_id = decisions[0].correlation_id
    agent_id = decisions[0].agent_id
    missing: list[str] = []

    # ── Manifest snapshot as evaluated (WS2 retained input) ──────────────
    retained = (
        await db.execute(
            select(EvaluationInputRecord).where(
                EvaluationInputRecord.correlation_id == correlation_id
            )
        )
    ).scalar_one_or_none()
    manifest_snapshot: dict[str, Any] | None = None
    retained_info: dict[str, Any] | None = None
    if retained is None:
        manifest_link = ChainLink(
            status="absent",
            detail=(
                "No retained evaluation input exists for this action "
                "(retention was off, or the decision predates retention); "
                "the manifest snapshot as evaluated is not recorded."
            ),
        )
        missing.append("manifest_snapshot")
    else:
        retained_info = {
            "payload_sha256": retained.payload_sha256,
            "state": retained.state,
            "recorded_decision": retained.recorded_decision,
            "enforcement_mode": retained.enforcement_mode,
            "retained_at": retained.retained_at.isoformat() if retained.retained_at else None,
            "purged_at": retained.purged_at.isoformat() if retained.purged_at else None,
        }
        if retained.payload and isinstance(retained.payload.get("agent"), dict):
            manifest_snapshot = retained.payload["agent"]
            manifest_link = ChainLink(
                status="present",
                detail="Manifest snapshot from the retained evaluation input (WS2).",
            )
        else:
            manifest_link = ChainLink(
                status="absent",
                detail=(
                    "The retained evaluation input was purged; only its "
                    "payload hash survives, so the manifest snapshot as "
                    "evaluated is no longer available."
                ),
            )
            missing.append("manifest_snapshot")

    # ── Policy identity ───────────────────────────────────────────────────
    policy_ids = sorted({d.policy_id for d in decisions})
    approval_result = await db.execute(
        select(ApprovalRequestRecord)
        .where(ApprovalRequestRecord.correlation_id == correlation_id)
        .order_by(ApprovalRequestRecord.created_at.asc())
    )
    approvals = list(approval_result.scalars().all())
    bundle_identifier: dict[str, Any] | None = None
    for approval in approvals:
        snapshot = approval.authorization_snapshot or {}
        if isinstance(snapshot.get("policy_identity"), dict):
            bundle_identifier = snapshot["policy_identity"]
            break
    if bundle_identifier is not None:
        policy_link = ChainLink(
            status="present",
            detail="Policy bundle identity from the approval authorization snapshot.",
        )
    else:
        policy_link = ChainLink(
            status="absent",
            detail=(
                "Decision rows record policy_id only; the policy bundle "
                "identity is recorded on approval authorization snapshots, "
                "and this action has none carrying one."
            ),
        )
        missing.append("policy_bundle_identifier")

    # ── Approval + execution receipt ──────────────────────────────────────
    approval_dict: dict[str, Any] | None = None
    receipt_dict: dict[str, Any] | None = None
    if approvals:
        approval_dict = _approval_dict(approvals[0])
        approval_link = ChainLink(
            status="present",
            detail=f"{len(approvals)} approval request(s) recorded for this action.",
        )
        receipt = (
            await db.execute(
                select(ExecutionReceiptRecord).where(
                    ExecutionReceiptRecord.approval_request_id == approvals[0].request_id
                )
            )
        ).scalar_one_or_none()
        if receipt is not None:
            receipt_dict = _receipt_dict(receipt)
            execution_link = ChainLink(status="present", detail="Execution receipt recorded.")
        else:
            execution_link = ChainLink(
                status="absent",
                detail="No execution receipt exists for this approval (no dispatch recorded).",
            )
            missing.append("execution_receipt")
    else:
        approval_link = ChainLink(
            status="absent",
            detail="No approval request was created for this action.",
        )
        missing.append("approval")
        execution_link = ChainLink(
            status="absent",
            detail="No execution receipt exists (execution receipts attach to approvals).",
        )
        missing.append("execution_receipt")

    # ── Telemetry events ──────────────────────────────────────────────────
    events_result = await db.execute(
        select(TelemetryEventRecord)
        .where(TelemetryEventRecord.correlation_id == correlation_id)
        .order_by(TelemetryEventRecord.created_at.asc())
    )
    events = [record.payload for record in events_result.scalars().all()]
    if events:
        telemetry_link = ChainLink(
            status="present", detail=f"{len(events)} telemetry event(s) recorded."
        )
    else:
        telemetry_link = ChainLink(
            status="absent",
            detail="No telemetry events were persisted for this correlation.",
        )
        missing.append("telemetry_events")

    logger.info(
        "decision_explorer_chain_read",
        actor=actor,
        correlation_id=correlation_id,
        agent_id=agent_id,
        decisions=len(decisions),
        missing_links=missing,
    )
    return DecisionChain(
        identifier=identifier,
        correlation_id=correlation_id,
        agent_id=agent_id,
        manifest_snapshot=manifest_snapshot,
        manifest_link=manifest_link,
        retained_input=retained_info,
        policy_ids=policy_ids,
        policy_bundle_identifier=bundle_identifier,
        policy_link=policy_link,
        decisions=[_summary(d) for d in decisions],
        approval=approval_dict,
        approval_link=approval_link,
        execution_receipt=receipt_dict,
        execution_link=execution_link,
        telemetry_events=events,
        telemetry_link=telemetry_link,
        missing_links=missing,
    )


async def get_agent_manifest(db: AsyncSession, agent_id: str) -> AgentRecord | None:
    result = await db.execute(select(AgentRecord).where(AgentRecord.agent_id == agent_id))
    return result.scalar_one_or_none()
