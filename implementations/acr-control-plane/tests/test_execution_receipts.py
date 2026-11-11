"""Dispatch fence durability and concurrency, without any external executor."""

import asyncio
from unittest.mock import AsyncMock

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from acr.common.errors import ApprovalConflictError
from acr.db.database import Base
from acr.pillar6_authority.receipts import (
    claim_execution,
    finish_execution,
    get_execution_receipt,
)


async def test_claim_is_committed_before_dispatch(db, test_engine):
    receipt = await claim_execution(
        db,
        approval_request_id="apr-durable",
        payload_hash="a" * 64,
        authorization_snapshot={"policy": "v1", "decided_by": "operator"},
    )
    async with async_sessionmaker(test_engine, expire_on_commit=False)() as observer:
        saved = await get_execution_receipt(observer, "apr-durable")
        assert saved.attempt_id == receipt.attempt_id
        assert saved.state == "executing"
        assert saved.authorization_snapshot["decided_by"] == "operator"
    await db.rollback()  # A caller crash/rollback cannot remove the committed fence.
    assert (await get_execution_receipt(db, "apr-durable")).state == "executing"


async def test_duplicate_claim_never_grants_new_dispatch(db):
    for expected in ("executing", "unknown", "blocked"):
        request_id = f"apr-{expected}"
        receipt = await claim_execution(
            db,
            approval_request_id=request_id,
            payload_hash="a" * 64,
            authorization_snapshot={},
        )
        if expected in {"unknown", "blocked"}:
            await finish_execution(db, receipt, state=expected, error="fixture_reason")
        with pytest.raises(ApprovalConflictError):
            await claim_execution(
                db,
                approval_request_id=request_id,
                payload_hash="a" * 64,
                authorization_snapshot={},
            )
        assert (await get_execution_receipt(db, request_id)).state == expected


async def test_success_and_evidence_survive_new_session(db, test_engine):
    receipt = await claim_execution(
        db,
        approval_request_id="apr-result",
        payload_hash="b" * 64,
        authorization_snapshot={"policy": "v1"},
    )
    await finish_execution(db, receipt, state="succeeded", result={"reference": "safe-fixture"})
    async with async_sessionmaker(test_engine, expire_on_commit=False)() as observer:
        saved = await get_execution_receipt(observer, "apr-result")
        assert saved.state == "succeeded"
        assert saved.result == {"reference": "safe-fixture"}
        assert saved.completed_at is not None
    with pytest.raises(ApprovalConflictError):
        await finish_execution(db, receipt, state="unknown", error="must-not-overwrite")
    assert (await get_execution_receipt(db, "apr-result")).state == "succeeded"


async def test_commit_failure_cannot_return_dispatch_right(db, monkeypatch):
    monkeypatch.setattr(db, "commit", AsyncMock(side_effect=RuntimeError("storage unavailable")))
    with pytest.raises(RuntimeError, match="storage unavailable"):
        await claim_execution(
            db,
            approval_request_id="apr-storage",
            payload_hash="a" * 64,
            authorization_snapshot={},
        )


async def test_concurrent_claims_grant_only_one_dispatch(tmp_path):
    # Separate real DB connections, unlike the in-memory StaticPool fixture.
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'receipts.sqlite'}")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)

    async def contender():
        async with factory() as session:
            try:
                await claim_execution(
                    session,
                    approval_request_id="apr-race",
                    payload_hash="a" * 64,
                    authorization_snapshot={},
                )
                return "dispatch"
            except ApprovalConflictError:
                return "blocked"

    try:
        results = await asyncio.gather(contender(), contender())
        assert sorted(results) == ["blocked", "dispatch"]
    finally:
        await engine.dispose()


async def test_blocked_receipt_records_no_dispatch_and_cannot_be_reopened(db):
    receipt = await claim_execution(
        db,
        approval_request_id="apr-final-check",
        payload_hash="a" * 64,
        authorization_snapshot={"policy": "v1"},
    )
    await finish_execution(db, receipt, state="blocked", error="authorization_changed")
    saved = await get_execution_receipt(db, "apr-final-check")
    assert saved.state == "blocked"
    assert saved.result is None
    assert saved.error == "authorization_changed"
    assert saved.completed_at is not None
    with pytest.raises(ApprovalConflictError):
        await finish_execution(db, receipt, state="succeeded", result={"invalid": True})
    assert (await get_execution_receipt(db, "apr-final-check")).state == "blocked"
