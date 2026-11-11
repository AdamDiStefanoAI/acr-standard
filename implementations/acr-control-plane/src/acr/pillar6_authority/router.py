"""Pillar 6: Human Authority API — approve, deny, override, list."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from acr.common.operator_auth import OperatorPrincipal, require_operator_roles
from acr.config import settings
from acr.db.database import get_db
from acr.pillar6_authority import approval as ap
from acr.pillar6_authority.models import ApprovalDecision, ApprovalResponse

router = APIRouter(prefix="/acr/approvals", tags=["Authority"])


def _to_response(record) -> ApprovalResponse:
    return ApprovalResponse(
        request_id=record.request_id,
        correlation_id=record.correlation_id,
        agent_id=record.agent_id,
        tool_name=record.tool_name,
        parameters=record.parameters or {},
        description=record.description,
        risk_tier=record.risk_tier,
        approval_queue=record.approval_queue,
        status=record.status,
        decision=record.decision,
        decided_by=record.decided_by,
        decision_reason=record.decision_reason,
        sla_minutes=record.sla_minutes,
        expires_at=record.expires_at,
        decided_at=record.decided_at,
        created_at=record.created_at,
        execution_result=record.execution_result,
    )


@router.get("", response_model=list[ApprovalResponse])
async def list_pending(
    db: AsyncSession = Depends(get_db),
    principal: OperatorPrincipal = Depends(
        require_operator_roles("approver", "auditor", "security_admin")
    ),
) -> list[ApprovalResponse]:
    records = await ap.list_pending_approvals(db)
    return [_to_response(r) for r in records]


@router.get("/{request_id}", response_model=ApprovalResponse)
async def get_approval(
    request_id: str,
    db: AsyncSession = Depends(get_db),
    principal: OperatorPrincipal = Depends(
        require_operator_roles("approver", "auditor", "security_admin")
    ),
) -> ApprovalResponse:
    record = await ap.get_approval_request(db, request_id)
    return _to_response(record)


@router.post("/{request_id}/approve", response_model=ApprovalResponse)
async def approve(
    request_id: str,
    body: ApprovalDecision,
    db: AsyncSession = Depends(get_db),
    principal: OperatorPrincipal = Depends(require_operator_roles("approver", "security_admin")),
) -> ApprovalResponse:
    record = await ap.approve(db, request_id, principal.subject, body.reason)
    if settings.execute_allowed_actions:
        await ap.execute_approval(db, record)
    await db.commit()
    await db.refresh(record)
    return _to_response(record)


@router.post("/{request_id}/deny", response_model=ApprovalResponse)
async def deny(
    request_id: str,
    body: ApprovalDecision,
    db: AsyncSession = Depends(get_db),
    principal: OperatorPrincipal = Depends(require_operator_roles("approver", "security_admin")),
) -> ApprovalResponse:
    record = await ap.deny(db, request_id, principal.subject, body.reason)
    await db.commit()
    await db.refresh(record)
    return _to_response(record)


@router.post("/{request_id}/override", response_model=ApprovalResponse)
async def override(
    request_id: str,
    body: ApprovalDecision,
    db: AsyncSession = Depends(get_db),
    principal: OperatorPrincipal = Depends(require_operator_roles("security_admin")),
) -> ApprovalResponse:
    """Break-glass override. Requires reason and operator identity. Always logged."""
    if not body.reason:
        from fastapi import HTTPException

        raise HTTPException(status_code=422, detail="Break-glass override requires a reason")
    record = await ap.override(db, request_id, principal.subject, body.reason)
    if settings.execute_allowed_actions:
        await ap.execute_approval(db, record)
    await db.commit()
    await db.refresh(record)
    return _to_response(record)


@router.post("/{request_id}/execute", response_model=ApprovalResponse)
async def resume_execution(
    request_id: str,
    db: AsyncSession = Depends(get_db),
    principal: OperatorPrincipal = Depends(require_operator_roles("approver", "security_admin")),
) -> ApprovalResponse:
    """Resume a recorded approval or retrieve its successful durable outcome."""
    from fastapi import HTTPException

    if not settings.execute_allowed_actions:
        raise HTTPException(status_code=409, detail="Downstream execution is disabled")
    record = await ap.get_approval_request(db, request_id)
    await ap.execute_approval(db, record)
    await db.refresh(record)
    return _to_response(record)


@router.get("/{request_id}/receipt")
async def get_receipt(
    request_id: str,
    db: AsyncSession = Depends(get_db),
    principal: OperatorPrincipal = Depends(
        require_operator_roles("approver", "auditor", "security_admin")
    ),
) -> dict:
    """Return durable dispatch evidence; executing/unknown requires reconciliation."""
    from fastapi import HTTPException

    from acr.pillar6_authority.receipts import get_execution_receipt

    receipt = await get_execution_receipt(db, request_id)
    if receipt is None:
        raise HTTPException(status_code=404, detail="No execution receipt")
    return {
        "attempt_id": receipt.attempt_id,
        "approval_request_id": receipt.approval_request_id,
        "payload_hash": receipt.payload_hash,
        "authorization_snapshot": receipt.authorization_snapshot,
        "state": receipt.state,
        "result": receipt.result,
        "error": receipt.error,
        "created_at": receipt.created_at,
        "completed_at": receipt.completed_at,
    }
