"""Pass/fail contract: revoked, stale, modified, expired actions never dispatch;
crash/timeout after dispatch cannot authorize a duplicate business effect.
"""

from datetime import timedelta
from unittest.mock import AsyncMock

import pytest
from fakeredis.aioredis import FakeRedis

from acr.common.errors import ACRError, ApprovalConflictError
from acr.common.time import utcnow
from acr.pillar1_identity.registry import get_manifest
from acr.pillar2_policy.models import PolicyEvaluationResult
from acr.pillar6_authority import approval as ap
from acr.pillar6_authority import receipts, resumption

POLICY = {"core": "core", "operator": "operator", "studio": "studio"}
STATE = {"isolate": None, "restrict": None, "throttle": None}


@pytest.fixture
async def prepared(db, sample_agent, monkeypatch):
    redis = FakeRedis(decode_responses=True)
    monkeypatch.setattr(resumption, "get_redis_or_none", lambda: redis)
    monkeypatch.setattr(resumption, "is_agent_killed", AsyncMock(return_value=False))
    monkeypatch.setattr(resumption, "expected_policy_identity", AsyncMock(return_value=POLICY))
    policy = AsyncMock(
        return_value=PolicyEvaluationResult(
            final_decision="escalate",
            decisions=[],
            approval_queue="finance",
            policy_identity=POLICY,
        )
    )
    monkeypatch.setattr(resumption, "evaluate_policy", policy)
    monkeypatch.setattr(
        resumption, "get_authoritative_projected_spend", AsyncMock(return_value=0.25)
    )
    monkeypatch.setattr(ap, "adjust_authoritative_spend", AsyncMock())
    executor = AsyncMock(return_value={"refund_id": "fixture-123"})
    monkeypatch.setattr(ap, "execute_action", executor)
    manifest = await get_manifest(db, sample_agent.agent_id)
    record = await ap.create_approval_request(
        db,
        correlation_id="resume-test",
        agent_id=sample_agent.agent_id,
        tool_name="issue_refund",
        parameters={"amount": 250},
        description="Fixture refund",
        approval_queue="finance",
        sla_minutes=60,
        authorization_snapshot=resumption.authorization_snapshot(manifest, POLICY, STATE),
        request_context={"tenant": "fixture"},
    )
    await db.commit()
    await ap.approve(db, record.request_id, "fixture-operator", "Fixture approval")
    await db.commit()
    yield record, executor, policy, redis
    await redis.aclose()


async def test_success_is_durable_and_replay_returns_same_result(db, prepared):
    record, executor, policy, _ = prepared
    first = await ap.execute_approval(db, record)
    await db.rollback()
    assert await ap.execute_approval(db, record) == first
    assert executor.await_count == 1
    assert executor.call_args.kwargs["parameters"] == {"amount": 250}
    receipt = await receipts.get_execution_receipt(db, record.request_id)
    assert receipt.state == "succeeded"
    assert receipt.authorization_snapshot["decided_by"] == "fixture-operator"
    assert policy.call_args.args[2]["tenant"] == "fixture"


@pytest.mark.parametrize(
    "change",
    [
        "payload",
        "context",
        "queue",
        "expiry",
        "legacy",
        "manifest",
        "killed",
        "isolate",
        "restrict",
        "throttle",
        "policy",
        "stale_evaluator",
        "deny",
        "modify",
        "queue_policy",
        "filter",
        "dependency",
    ],
)
async def test_changed_authority_blocks_side_effect(
    db, prepared, sample_agent, monkeypatch, change
):
    record, executor, policy, redis = prepared
    if change == "payload":
        record.parameters = {"amount": 999}
    elif change == "context":
        record.request_context = {"tenant": "other"}
    elif change == "queue":
        record.approval_queue = "other"
    elif change == "expiry":
        record.expires_at = utcnow() - timedelta(seconds=1)
    elif change == "legacy":
        record.authorization_snapshot = None
    elif change == "manifest":
        sample_agent.is_active = False
        await db.flush()
    elif change == "killed":
        monkeypatch.setattr(resumption, "is_agent_killed", AsyncMock(return_value=True))
    elif change in {"isolate", "restrict", "throttle"}:
        prefix = {
            "isolate": resumption._ISOLATE_PREFIX,
            "restrict": resumption._RESTRICT_PREFIX,
            "throttle": resumption._THROTTLE_PREFIX,
        }[change]
        await redis.set(
            prefix + record.agent_id, {"isolate": "1", "restrict": "[]", "throttle": "50"}[change]
        )
    elif change == "policy":
        monkeypatch.setattr(
            resumption,
            "expected_policy_identity",
            AsyncMock(return_value={**POLICY, "studio": "new"}),
        )
    elif change == "stale_evaluator":
        policy.return_value.policy_identity = None
    elif change in {"deny", "modify"}:
        policy.return_value.final_decision = change
    elif change == "queue_policy":
        policy.return_value.approval_queue = "new-queue"
    elif change == "filter":
        from types import SimpleNamespace

        monkeypatch.setattr(
            resumption,
            "filter_parameters",
            lambda *a: SimpleNamespace(parameters={"redacted": True}),
        )
    elif change == "dependency":
        monkeypatch.setattr(resumption, "get_redis_or_none", lambda: None)
    with pytest.raises(ACRError):
        await ap.execute_approval(db, record)
    executor.assert_not_awaited()
    assert await receipts.get_execution_receipt(db, record.request_id) is None


async def test_response_lost_never_retries_side_effect(db, prepared):
    record, executor, _, _ = prepared
    effects = []

    async def commit_then_timeout(**payload):
        effects.append(payload)
        raise TimeoutError("response lost after external commit")

    executor.side_effect = commit_then_timeout
    with pytest.raises(TimeoutError):
        await ap.execute_approval(db, record)
    await db.rollback()
    with pytest.raises(ApprovalConflictError, match="reconciliation"):
        await ap.execute_approval(db, record)
    assert len(effects) == 1
    assert (await receipts.get_execution_receipt(db, record.request_id)).state == "unknown"


async def test_crash_claim_requires_reconciliation(db, prepared):
    record, executor, _, _ = prepared
    await receipts.claim_execution(
        db,
        approval_request_id=record.request_id,
        payload_hash=resumption.digest(resumption.action_payload(record)),
        authorization_snapshot={},
    )
    with pytest.raises(ApprovalConflictError, match="reconciliation"):
        await ap.execute_approval(db, record)
    executor.assert_not_awaited()


async def test_storage_failure_prevents_execution(db, prepared, monkeypatch):
    record, executor, _, _ = prepared
    monkeypatch.setattr(
        receipts, "claim_execution", AsyncMock(side_effect=OSError("storage unavailable"))
    )
    with pytest.raises(OSError):
        await ap.execute_approval(db, record)
    executor.assert_not_awaited()


async def test_completion_storage_failure_retains_claim(db, prepared, monkeypatch):
    record, executor, _, _ = prepared
    monkeypatch.setattr(
        receipts, "finish_execution", AsyncMock(side_effect=OSError("storage unavailable"))
    )
    with pytest.raises(OSError):
        await ap.execute_approval(db, record)
    await db.rollback()
    await db.refresh(record)
    with pytest.raises(ApprovalConflictError):
        await ap.execute_approval(db, record)
    assert executor.await_count == 1


@pytest.mark.parametrize("during", ["opa", "claim"])
async def test_revocation_during_async_work_blocks_dispatch(db, prepared, monkeypatch, during):
    record, executor, policy, redis = prepared
    if during == "opa":

        async def revoke(*args):
            await redis.set(resumption._ISOLATE_PREFIX + record.agent_id, "1")
            return policy.return_value

        policy.side_effect = revoke
    else:
        original_claim = receipts.claim_execution

        async def revoke_after_claim(*args, **kwargs):
            receipt = await original_claim(*args, **kwargs)
            await redis.set(resumption._ISOLATE_PREFIX + record.agent_id, "1")
            return receipt

        monkeypatch.setattr(receipts, "claim_execution", revoke_after_claim)
    with pytest.raises(ApprovalConflictError):
        await ap.execute_approval(db, record)
    executor.assert_not_awaited()
    assert (await receipts.get_execution_receipt(db, record.request_id)).state == "blocked"


async def test_expired_approval_cannot_be_approved_or_overridden(db, sample_agent):
    record = await ap.create_approval_request(
        db,
        correlation_id="expired",
        agent_id=sample_agent.agent_id,
        tool_name="issue_refund",
        parameters={},
        description=None,
        approval_queue="default",
        sla_minutes=60,
    )
    record.expires_at = utcnow() - timedelta(seconds=1)
    record.request_payload_hash = resumption.request_digest(record)
    await db.commit()
    for decide in (ap.approve, ap.override):
        with pytest.raises(ApprovalConflictError, match="expired"):
            await decide(db, record.request_id, "operator", "emergency")


async def test_resume_http_and_receipt_use_stored_result(async_client, prepared, monkeypatch):
    from acr.config import settings

    record, executor, _, _ = prepared
    monkeypatch.setattr(settings, "execute_allowed_actions", True)
    for _ in range(2):
        response = await async_client.post(f"/acr/approvals/{record.request_id}/execute")
        assert response.status_code == 200, response.text
        assert response.json()["execution_result"] == {"refund_id": "fixture-123"}
    receipt = await async_client.get(f"/acr/approvals/{record.request_id}/receipt")
    assert receipt.status_code == 200
    assert receipt.json()["state"] == "succeeded"
    assert receipt.json()["authorization_snapshot"]["approved_payload"]["parameters"] == {
        "amount": 250
    }
    assert executor.await_count == 1


async def test_receipt_retains_action_after_approval_deletion(db, prepared):
    record, _, _, _ = prepared
    request_id = record.request_id
    await ap.execute_approval(db, record)
    await db.delete(record)
    await db.commit()
    receipt = await receipts.get_execution_receipt(db, request_id)
    payload = receipt.authorization_snapshot["approved_payload"]
    assert payload["agent_id"] == "customer-support-01"
    assert payload["tool_name"] == "issue_refund"
    assert payload["parameters"] == {"amount": 250}


class TestConcurrentResume:
    @pytest.fixture
    async def test_engine(self, tmp_path):
        from sqlalchemy.ext.asyncio import create_async_engine

        from acr.db.database import Base

        engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'resume.sqlite'}")
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        yield engine
        await engine.dispose()

    async def test_two_sessions_dispatch_one_effect(self, prepared, test_engine):
        import asyncio

        from sqlalchemy.ext.asyncio import async_sessionmaker

        record, executor, policy, _ = prepared
        request_id = record.request_id
        ready = asyncio.Event()
        reached = 0

        async def both_evaluate(*args):
            nonlocal reached
            reached += 1
            if reached == 2:
                ready.set()
            await asyncio.wait_for(ready.wait(), 5)
            return policy.return_value

        policy.side_effect = both_evaluate
        factory = async_sessionmaker(test_engine, expire_on_commit=False)

        async def run():
            async with factory() as session:
                current = await ap.get_approval_request(session, request_id)
                return await ap.execute_approval(session, current)

        outcomes = await asyncio.gather(run(), run(), return_exceptions=True)
        assert sum(isinstance(value, dict) for value in outcomes) == 1
        assert sum(isinstance(value, ApprovalConflictError) for value in outcomes) == 1
        assert executor.await_count == 1
