"""Integration outbox: enqueue (producer side) + worker (delivery side).

Producer side — `enqueue_event` is called by the approval, containment,
killswitch, and decision-recording paths. It writes inside a SAVEPOINT
and swallows every failure (logging it), so an integration problem can
never break, block, or alter the path that produced the event. When no
relevant integration is enabled the producers do not call it at all.

Worker side — `process_outbox_once` drains due rows: claim (atomically,
so exactly one of the gateway's worker loops owns each row), deliver via
the integration's sender, record an attempt row either way, retry with
exponential backoff, and dead-letter after the configured maximum
attempts with the failure kept on the row. Delivery is evidence: every
attempt lands in integration_delivery_attempts.
"""

from __future__ import annotations

from datetime import timedelta

import httpx
import structlog
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from acr.common.time import utcnow
from acr.config import settings
from acr.db.models import IntegrationDeliveryAttemptRecord, IntegrationOutboxRecord

logger = structlog.get_logger(__name__)


class DeliveryError(Exception):
    """A delivery attempt failed. `retryable=False` dead-letters at once."""

    def __init__(self, message: str, *, http_status: int | None = None, retryable: bool = True):
        super().__init__(message)
        self.http_status = http_status
        self.retryable = retryable


async def enqueue_event(
    db: AsyncSession,
    *,
    integration: str,
    event_type: str,
    reference: str,
    payload: dict,
    target: str = "",
    correlation_id: str | None = None,
) -> IntegrationOutboxRecord | None:
    """Best-effort outbox insert. Returns the row, or None on any failure.

    Duplicate (integration, event_type, reference) inserts are treated as
    success-with-no-row: the event is already queued exactly once.
    """
    try:
        async with db.begin_nested():
            row = IntegrationOutboxRecord(
                integration=integration,
                event_type=event_type,
                reference=reference,
                correlation_id=correlation_id,
                target=target,
                payload=payload,
            )
            db.add(row)
            await db.flush()
        return row
    except Exception as exc:  # enqueue must never break the producing path
        logger.warning(
            "integration_enqueue_failed",
            integration=integration,
            event_type=event_type,
            reference=reference,
            error=str(exc),
        )
        return None


def _backoff_seconds(attempts: int) -> int:
    base = max(1, settings.integrations_outbox_backoff_base_seconds)
    return min(base * (2 ** max(0, attempts - 1)), 3600)


async def _record_attempt(
    db: AsyncSession,
    row: IntegrationOutboxRecord,
    *,
    result: str,
    http_status: int | None,
    error: str | None,
) -> None:
    db.add(
        IntegrationDeliveryAttemptRecord(
            outbox_id=row.id,
            attempt_number=row.attempts,
            result=result,
            http_status=http_status,
            error=error,
        )
    )
    await db.flush()


async def _apply_failure(db: AsyncSession, row: IntegrationOutboxRecord, exc: Exception) -> None:
    http_status = getattr(exc, "http_status", None)
    retryable = getattr(exc, "retryable", True)
    row.last_error = str(exc)[:2000]
    await _record_attempt(db, row, result="failure", http_status=http_status, error=row.last_error)
    if not retryable or row.attempts >= max(1, settings.integrations_outbox_max_attempts):
        row.status = "dead_letter"
        logger.error(
            "integration_delivery_dead_letter",
            integration=row.integration,
            event_type=row.event_type,
            reference=row.reference,
            attempts=row.attempts,
            error=row.last_error,
        )
    else:
        row.status = "pending"
        row.next_attempt_at = utcnow() + timedelta(seconds=_backoff_seconds(row.attempts))
    await db.commit()


async def _apply_success(
    db: AsyncSession,
    row: IntegrationOutboxRecord,
    delivery_ref: dict | None,
    http_status: int | None = 200,
) -> None:
    row.status = "delivered"
    row.delivered_at = utcnow()
    row.last_error = None
    if delivery_ref is not None:
        row.delivery_ref = delivery_ref
    await _record_attempt(db, row, result="success", http_status=http_status, error=None)
    await db.commit()


async def _deliver_one(
    db: AsyncSession, row: IntegrationOutboxRecord, client: httpx.AsyncClient
) -> None:
    from acr.integrations import servicenow, slack, syslog, teams

    senders = {
        "slack": slack.deliver,
        "teams": teams.deliver,
        "servicenow": servicenow.deliver,
        "syslog": syslog.deliver,
    }
    sender = senders.get(row.integration)
    if sender is None:
        raise DeliveryError(f"No sender for integration '{row.integration}'", retryable=False)
    delivery_ref = await sender(db, row, client)
    await _apply_success(db, row, delivery_ref)


async def _deliver_batch(
    db: AsyncSession,
    rows: list[IntegrationOutboxRecord],
    client: httpx.AsyncClient,
    deliver_batch,
) -> None:
    """Batched rows: one request carries many records (Sentinel Logs
    Ingestion, Splunk HEC).

    Rows arrive already claimed by `_claim_due` (status 'delivering',
    attempt counter incremented). Each row still gets its own attempt
    record and its own retry state — batching changes the HTTP shape,
    never the evidence shape.
    """
    try:
        await deliver_batch(rows, client)
    except Exception as exc:
        for row in rows:
            await _apply_failure(db, row, exc)
        return
    for row in rows:
        await _apply_success(db, row, None)


async def _deliver_sentinel_batch(
    db: AsyncSession, rows: list[IntegrationOutboxRecord], client: httpx.AsyncClient
) -> None:
    from acr.integrations import sentinel

    await _deliver_batch(db, rows, client, sentinel.deliver_batch)


async def _deliver_splunk_batch(
    db: AsyncSession, rows: list[IntegrationOutboxRecord], client: httpx.AsyncClient
) -> None:
    from acr.integrations import splunk

    await _deliver_batch(db, rows, client, splunk.deliver_batch)


async def _claim_due(db: AsyncSession, limit: int = 500) -> list[IntegrationOutboxRecord]:
    """Atomically claim due pending rows for this drainer.

    A single conditional UPDATE flips due rows to 'delivering' and
    increments their attempt counter; the id subquery takes
    FOR UPDATE SKIP LOCKED on Postgres so concurrent drainers (the
    gateway runs multiple uvicorn workers, each with its own lifespan
    loop) partition the due set instead of claiming the same row twice
    — a row is delivered by exactly one drainer. Claiming is committed
    before any delivery starts, so a claimed row is invisible to other
    drainers even while its HTTP call is still in flight.
    """
    now = utcnow()
    due_ids = (
        select(IntegrationOutboxRecord.id)
        .where(
            IntegrationOutboxRecord.status == "pending",
            IntegrationOutboxRecord.next_attempt_at <= now,
        )
        .order_by(IntegrationOutboxRecord.created_at.asc())
        .limit(limit)
    )
    if db.get_bind().dialect.name == "postgresql":
        due_ids = due_ids.with_for_update(skip_locked=True)
    result = await db.execute(
        update(IntegrationOutboxRecord)
        .where(
            IntegrationOutboxRecord.id.in_(due_ids.scalar_subquery()),
            IntegrationOutboxRecord.status == "pending",
        )
        .values(
            status="delivering",
            attempts=IntegrationOutboxRecord.attempts + 1,
        )
        .returning(IntegrationOutboxRecord.id)
        .execution_options(synchronize_session=False)
    )
    claimed_ids = list(result.scalars().all())
    await db.commit()
    if not claimed_ids:
        return []
    rows = list(
        (
            await db.execute(
                select(IntegrationOutboxRecord)
                .where(IntegrationOutboxRecord.id.in_(claimed_ids))
                # The caller's session may already hold these instances
                # in an expired state (any rollback expires them); the
                # claim must hand the drainer the committed truth.
                .execution_options(populate_existing=True)
            )
        )
        .scalars()
        .all()
    )
    rows.sort(key=lambda r: r.created_at)
    return rows


async def process_outbox_once(
    db: AsyncSession, client: httpx.AsyncClient | None = None
) -> dict[str, int]:
    """Deliver every due outbox row once. Returns outcome counts.

    Safe to call from the lifespan loop and from tests. A failure on one
    row never stops the drain of the others.
    """
    owns_client = client is None
    if owns_client:
        client = httpx.AsyncClient(timeout=10.0)
    counts = {"delivered": 0, "failed": 0, "dead_letter": 0}
    try:
        due = await _claim_due(db)

        def _tally(batch: list[IntegrationOutboxRecord]) -> None:
            for row in batch:
                if row.status == "delivered":
                    counts["delivered"] += 1
                elif row.status == "dead_letter":
                    counts["dead_letter"] += 1
                else:
                    counts["failed"] += 1

        sentinel_rows = [r for r in due if r.integration == "sentinel"]
        splunk_rows = [r for r in due if r.integration == "splunk"]
        other_rows = [r for r in due if r.integration not in ("sentinel", "splunk")]
        batch_size = max(1, settings.sentinel_batch_max)
        for start in range(0, len(sentinel_rows), batch_size):
            batch = sentinel_rows[start : start + batch_size]
            await _deliver_sentinel_batch(db, batch, client)
            _tally(batch)
        splunk_batch_size = max(1, settings.splunk_hec_batch_max)
        for start in range(0, len(splunk_rows), splunk_batch_size):
            batch = splunk_rows[start : start + splunk_batch_size]
            await _deliver_splunk_batch(db, batch, client)
            _tally(batch)

        for row in other_rows:
            # The row was claimed (and the claim committed) by
            # _claim_due before delivery, so it survives the rollback
            # below; reload it and record the failed attempt against
            # it. Capture the id now: the rollback expires ORM state.
            row_id = row.id
            try:
                await _deliver_one(db, row, client)
                counts["delivered"] += 1
            except Exception as exc:
                await db.rollback()
                row = await db.get(IntegrationOutboxRecord, row_id)
                if row is None:
                    continue
                await _apply_failure(db, row, exc)
                if row.status == "dead_letter":
                    counts["dead_letter"] += 1
                else:
                    counts["failed"] += 1
        return counts
    finally:
        if owns_client:
            await client.aclose()
