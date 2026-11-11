"""Persist a dispatch fence before any external effect, then record its outcome.

These helpers commit their session, including pending approval changes. A caller
must never dispatch if claim_execution raises, even if the commit result is
uncertain. No retry or lease stealing is provided: an executing/unknown receipt
requires operator reconciliation, not another external call.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Literal

from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from acr.common.errors import ApprovalConflictError
from acr.common.time import utcnow
from acr.db.models import ExecutionReceiptRecord


async def get_execution_receipt(
    db: AsyncSession, approval_request_id: str
) -> ExecutionReceiptRecord | None:
    result = await db.execute(
        select(ExecutionReceiptRecord).where(
            ExecutionReceiptRecord.approval_request_id == approval_request_id
        )
    )
    return result.scalar_one_or_none()


async def claim_execution(
    db: AsyncSession,
    *,
    approval_request_id: str,
    payload_hash: str,
    authorization_snapshot: dict,
) -> ExecutionReceiptRecord:
    """Atomically claim and COMMIT one dispatch right. Never replay a prior claim."""
    receipt = ExecutionReceiptRecord(
        approval_request_id=approval_request_id,
        payload_hash=payload_hash,
        authorization_snapshot=deepcopy(authorization_snapshot),
        state="executing",
    )
    db.add(receipt)
    try:
        await db.commit()
    except IntegrityError as exc:
        await db.rollback()
        raise ApprovalConflictError(
            "Execution receipt already exists or could not be created; do not redispatch"
        ) from exc
    return receipt


async def finish_execution(
    db: AsyncSession,
    receipt: ExecutionReceiptRecord,
    *,
    state: Literal["succeeded", "unknown", "blocked"],
    result: dict | None = None,
    error: str | None = None,
) -> None:
    """Commit a terminal outcome once. A failed commit leaves a replay fence.

    Use blocked only when dispatch is known not to have started. Unknown covers
    any possible external effect; neither state permits another dispatch claim.
    """
    if state not in {"succeeded", "unknown", "blocked"}:
        raise ValueError("Execution outcome must be succeeded, unknown, or blocked")
    changed = await db.execute(
        update(ExecutionReceiptRecord)
        .where(
            ExecutionReceiptRecord.attempt_id == receipt.attempt_id,
            ExecutionReceiptRecord.state == "executing",
        )
        .values(state=state, result=deepcopy(result), error=error, completed_at=utcnow())
    )
    if changed.rowcount != 1:
        await db.rollback()
        raise ApprovalConflictError("Execution receipt is already finalized or missing")
    await db.commit()
