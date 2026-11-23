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

import uuid
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
    *,
    outbox_id: uuid.UUID,
    attempt_number: int,
    result: str,
    http_status: int | None,
    error: str | None,
) -> None:
    db.add(
        IntegrationDeliveryAttemptRecord(
            outbox_id=outbox_id,
            attempt_number=attempt_number,
            result=result,
            http_status=http_status,
            error=error,
        )
    )
    await db.flush()


async def _apply_failure(db: AsyncSession, row: IntegrationOutboxRecord, exc: Exception) -> str:
    """Record a failed delivery and commit. Returns the outcome string
    ("dead_letter" or "failed"), captured BEFORE the commit: callers
    tally from the return value and never re-read the row afterwards,
    because a later rollback in the same session expires every instance
    in it (rollback expires unconditionally, even with
    expire_on_commit=False).
    """
    row_id = row.id
    attempts = row.attempts
    http_status = getattr(exc, "http_status", None)
    retryable = getattr(exc, "retryable", True)
    row.last_error = str(exc)[:2000]
    await _record_attempt(
        db,
        outbox_id=row_id,
        attempt_number=attempts,
        result="failure",
        http_status=http_status,
        error=row.last_error,
    )
    if not retryable or attempts >= max(1, settings.integrations_outbox_max_attempts):
        row.status = "dead_letter"
        outcome = "dead_letter"
        logger.error(
            "integration_delivery_dead_letter",
            integration=row.integration,
            event_type=row.event_type,
            reference=row.reference,
            attempts=attempts,
            error=row.last_error,
        )
    else:
        row.status = "pending"
        row.next_attempt_at = utcnow() + timedelta(seconds=_backoff_seconds(attempts))
        outcome = "failed"
    await db.commit()
    return outcome


async def _apply_success(
    db: AsyncSession,
    row: IntegrationOutboxRecord,
    delivery_ref: dict | None,
    http_status: int | None = 200,
) -> str:
    """Record a successful delivery and commit. Returns "delivered",
    captured before the commit for the same reason as `_apply_failure`.
    """
    row_id = row.id
    attempts = row.attempts
    row.status = "delivered"
    row.delivered_at = utcnow()
    row.last_error = None
    if delivery_ref is not None:
        row.delivery_ref = delivery_ref
    await _record_attempt(
        db,
        outbox_id=row_id,
        attempt_number=attempts,
        result="success",
        http_status=http_status,
        error=None,
    )
    await db.commit()
    return "delivered"


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
) -> list[str]:
    """Batched rows: one request carries many records (Sentinel Logs
    Ingestion, Splunk HEC).

    Rows arrive already claimed by `_claim_due` (status 'delivering',
    attempt counter incremented). Each row still gets its own attempt
    record and its own retry state — batching changes the HTTP shape,
    never the evidence shape.

    Returns one outcome string per row ("delivered" / "failed" /
    "dead_letter"). Row ids are captured up front and each row is
    re-fetched by id before its outcome is applied: applying one row's
    outcome commits, and a rollback anywhere in the drain expires every
    instance held by the session, so the instances passed in cannot be
    trusted across iterations.
    """
    row_ids = [row.id for row in rows]
    try:
        await deliver_batch(rows, client)
    except Exception as exc:
        outcomes = []
        for row_id in row_ids:
            row = await db.get(IntegrationOutboxRecord, row_id)
            if row is None:
                continue
            outcomes.append(await _apply_failure(db, row, exc))
        return outcomes
    outcomes = []
    for row_id in row_ids:
        row = await db.get(IntegrationOutboxRecord, row_id)
        if row is None:
            continue
        outcomes.append(await _apply_success(db, row, None))
    return outcomes


async def _deliver_sentinel_batch(
    db: AsyncSession, rows: list[IntegrationOutboxRecord], client: httpx.AsyncClient
) -> list[str]:
    from acr.integrations import sentinel

    return await _deliver_batch(db, rows, client, sentinel.deliver_batch)


async def _deliver_splunk_batch(
    db: AsyncSession, rows: list[IntegrationOutboxRecord], client: httpx.AsyncClient
) -> list[str]:
    from acr.integrations import splunk

    return await _deliver_batch(db, rows, client, splunk.deliver_batch)


async def _refetch(db: AsyncSession, ids: list[uuid.UUID]) -> list[IntegrationOutboxRecord]:
    """Materialize rows by id, in id order, as fresh committed state.

    populate_existing overwrites any expired (or stale) copies the
    session already holds — after any rollback every instance in the
    session is expired, and reading an attribute off an expired
    instance outside an awaited SQLAlchemy call raises MissingGreenlet.
    """
    if not ids:
        return []
    rows = list(
        (
            await db.execute(
                select(IntegrationOutboxRecord)
                .where(IntegrationOutboxRecord.id.in_(ids))
                .execution_options(populate_existing=True)
            )
        )
        .scalars()
        .all()
    )
    by_id = {row.id: row for row in rows}
    return [by_id[row_id] for row_id in ids if row_id in by_id]


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
        # Capture plain values while the claimed instances are fresh,
        # and never read ORM attributes off `due` again: the per-row
        # rollback in the loop below expires EVERY instance in the
        # session (rollback expires unconditionally, even with
        # expire_on_commit=False), and touching an expired instance
        # outside an awaited SQLAlchemy call raises MissingGreenlet.
        # Everything downstream works from ids and re-fetches the row
        # it is about to touch.
        due_ids = [(row.id, row.integration, row.event_type) for row in due]
        sentinel_ids = [row_id for row_id, integration, _ in due_ids if integration == "sentinel"]
        splunk_ids = [row_id for row_id, integration, _ in due_ids if integration == "splunk"]
        other_entries = [
            (row_id, event_type)
            for row_id, integration, event_type in due_ids
            if integration not in ("sentinel", "splunk")
        ]
        # Causal order within the drain: an approval_decided delivery
        # updates the message its approval_requested row posted, so
        # when both are claimed in the same drain the original must be
        # delivered first — otherwise the update spuriously burns a
        # retry cycle on "not yet delivered". The claim's created_at
        # ordering cannot guarantee this (rows enqueued in the same
        # second tie, and the tie-break is arbitrary), so order the
        # phases explicitly. Stable sort: claim order is preserved
        # within each phase.
        _phase = {"approval_requested": 0, "approval_decided": 2}
        other_entries.sort(key=lambda entry: _phase.get(entry[1], 1))
        other_ids = [row_id for row_id, _ in other_entries]

        batch_size = max(1, settings.sentinel_batch_max)
        for start in range(0, len(sentinel_ids), batch_size):
            batch = await _refetch(db, sentinel_ids[start : start + batch_size])
            for outcome in await _deliver_sentinel_batch(db, batch, client):
                counts[outcome] += 1
        splunk_batch_size = max(1, settings.splunk_hec_batch_max)
        for start in range(0, len(splunk_ids), batch_size):
            batch = await _refetch(db, splunk_ids[start : start + splunk_batch_size])
            for outcome in await _deliver_splunk_batch(db, batch, client):
                counts[outcome] += 1

        for row_id in other_ids:
            row = await db.get(IntegrationOutboxRecord, row_id)
            if row is None:
                continue
            try:
                await _deliver_one(db, row, client)
                counts["delivered"] += 1
            except Exception as exc:
                await db.rollback()
                # The rollback expired every instance in the session,
                # including this row; re-fetch before recording the
                # failed attempt against it.
                row = await db.get(IntegrationOutboxRecord, row_id)
                if row is None:
                    continue
                outcome = await _apply_failure(db, row, exc)
                counts[outcome] += 1
        return counts
    finally:
        if owns_client:
            await client.aclose()
