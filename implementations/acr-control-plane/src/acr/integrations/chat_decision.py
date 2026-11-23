"""Chat decisions are clients of the pillar 6 approvals API — never a
side door around it.

A verified chat action is resolved by invoking the approvals API's own
route handlers with an OperatorPrincipal whose subject is the mapped
operator identity. Everything the API enforces therefore applies
identically: the pending-state check, resumption.check_request (expiry
+ payload-hash binding), the claim-once execution receipt, and the
execute-on-approve behavior. After a successful decision the transport
identity is stamped next to it (decided_channel, chat_actor_id);
decided_by remains the mapped operator subject.
"""

from __future__ import annotations

from dataclasses import dataclass

import structlog
from fastapi import HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from acr.common.errors import ACRError
from acr.common.operator_auth import OperatorPrincipal
from acr.db.models import ApprovalRequestRecord
from acr.pillar6_authority import approval as approval_service
from acr.pillar6_authority import router as authority_router
from acr.pillar6_authority.models import ApprovalDecision

logger = structlog.get_logger(__name__)


@dataclass
class ChatDecisionOutcome:
    record: ApprovalRequestRecord | None
    error: str | None = None

    @property
    def status(self) -> str:
        return self.record.status if self.record is not None else "unknown"


async def _current_record(db: AsyncSession, request_id: str) -> ApprovalRequestRecord | None:
    try:
        return await approval_service.get_approval_request(db, request_id)
    except ACRError:
        return None


async def decide_from_chat(
    db: AsyncSession,
    *,
    request_id: str,
    action: str,  # "approve" | "deny"
    channel: str,  # "slack" | "teams"
    chat_actor_id: str,
    operator_subject: str,
) -> ChatDecisionOutcome:
    """Decide an approval through the approvals API handlers.

    Never raises for business outcomes: already-decided, expired, and
    missing approvals come back as an outcome carrying the current
    record (when one exists) and the API's error message, so the caller
    can render the truth instead of inventing state.
    """
    principal = OperatorPrincipal(
        subject=operator_subject,
        roles=frozenset({"approver"}),
        source=channel,
    )
    handler = authority_router.approve if action == "approve" else authority_router.deny
    try:
        await handler(
            request_id=request_id,
            body=ApprovalDecision(reason=None),
            db=db,
            principal=principal,
        )
    except (ACRError, HTTPException) as exc:
        await db.rollback()
        message = exc.detail if isinstance(exc, HTTPException) else str(exc)
        logger.info(
            "chat_decision_rejected_by_approvals_api",
            channel=channel,
            request_id=request_id,
            chat_actor_id=chat_actor_id,
            operator_subject=operator_subject,
            error=str(message),
        )
        return ChatDecisionOutcome(record=await _current_record(db, request_id), error=str(message))

    record = await _current_record(db, request_id)
    if record is not None:
        record.decided_channel = channel
        record.chat_actor_id = chat_actor_id
        await db.commit()
        await db.refresh(record)
    logger.info(
        "chat_decision_applied",
        channel=channel,
        request_id=request_id,
        chat_actor_id=chat_actor_id,
        operator_subject=operator_subject,
        status=record.status if record else "unknown",
    )
    return ChatDecisionOutcome(record=record)
