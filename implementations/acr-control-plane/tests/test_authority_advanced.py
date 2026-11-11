"""Extended authority tests: tiering, override, expiry, HMAC signing, webhook."""

from __future__ import annotations

import hashlib
import hmac
import json
import uuid
from datetime import timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from acr.common.time import utcnow
from acr.db.database import Base
from acr.db.models import ApprovalRequestRecord
from acr.pillar6_authority.approval import (
    _sign_payload,
    create_approval_request,
    expire_timed_out_approvals,
    override,
)
from acr.pillar6_authority.tiering import classify_action

# ── DB fixture ────────────────────────────────────────────────────────────────


@pytest_asyncio.fixture
async def db():
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        echo=False,
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(bind=engine, expire_on_commit=False, class_=AsyncSession)
    async with factory() as session:
        yield session
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


# ── Helper ────────────────────────────────────────────────────────────────────


async def _make_approval(
    db: AsyncSession,
    *,
    status: str = "pending",
    already_expired: bool = False,
    agent_id: str = "test-agent",
) -> ApprovalRequestRecord:
    expires_at = (
        utcnow() - timedelta(minutes=5) if already_expired else utcnow() + timedelta(minutes=240)
    )
    record = ApprovalRequestRecord(
        request_id=f"apr-adv-{uuid.uuid4().hex}",
        correlation_id="corr-adv",
        agent_id=agent_id,
        tool_name="issue_refund",
        parameters={"amount": 500},
        approval_queue="finance",
        sla_minutes=240,
        expires_at=expires_at,
        status=status,
    )
    from acr.pillar6_authority.resumption import request_digest

    record.request_payload_hash = request_digest(record)
    db.add(record)
    await db.commit()
    await db.refresh(record)
    return record


# ── Tiering ───────────────────────────────────────────────────────────────────


class TestTiering:
    def test_high_risk_tool_always_needs_approval(self):
        for tool in ("delete_customer", "issue_refund", "execute_sql", "drop_table"):
            result = classify_action(tool, {}, "low")
            assert result.tier == "high", f"Expected high for {tool}"
            assert result.auto_approve is False
            assert result.sla_minutes == 240

    def test_high_risk_returns_correct_queue(self):
        result = classify_action("delete_customer", {}, "medium")
        assert result.approval_queue == "high-risk-approvals"

    def test_medium_risk_tool_low_tier_agent_auto_approved(self):
        """Medium-risk tool + low-risk agent → auto-approve (no queue)."""
        result = classify_action("send_email", {}, "low")
        assert result.auto_approve is True
        assert result.tier == "low"

    def test_medium_risk_tool_medium_tier_agent_auto_approved(self):
        result = classify_action("create_ticket", {}, "medium")
        assert result.auto_approve is True

    def test_medium_risk_tool_high_tier_agent_needs_approval(self):
        """Medium-risk tool + high-risk agent → require approval."""
        result = classify_action("send_email", {}, "high")
        assert result.tier == "medium"
        assert result.auto_approve is False
        assert result.approval_queue == "medium-risk-approvals"
        assert result.sla_minutes == 60

    def test_unknown_tool_is_low_risk(self):
        result = classify_action("query_customer_db", {}, "medium")
        assert result.tier == "low"
        assert result.auto_approve is True
        assert result.sla_minutes == 0

    def test_low_risk_tool_high_tier_agent_still_low(self):
        result = classify_action("unknown_read_tool", {}, "high")
        assert result.tier == "low"
        assert result.auto_approve is True


# ── HMAC signing ──────────────────────────────────────────────────────────────


class TestWebhookSigning:
    def test_sign_payload_produces_hmac_sha256(self):
        payload = {"event": "approval_request_created", "agent_id": "x", "amount": 100}
        secret = "my-test-secret"

        with patch("acr.pillar6_authority.approval.settings") as mock_settings:
            mock_settings.webhook_hmac_secret = secret
            sig = _sign_payload(payload)

        # Verify the signature independently
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        expected = hmac.new(secret.encode(), canonical.encode(), hashlib.sha256).hexdigest()
        assert sig == expected

    def test_sign_payload_key_order_independent(self):
        """Key order in the input dict must not affect the signature."""
        secret = "order-test-key"
        with patch("acr.pillar6_authority.approval.settings") as mock_settings:
            mock_settings.webhook_hmac_secret = secret
            sig1 = _sign_payload({"b": 2, "a": 1, "c": 3})
            sig2 = _sign_payload({"c": 3, "a": 1, "b": 2})
        assert sig1 == sig2

    def test_different_payloads_produce_different_signatures(self):
        secret = "diff-key"
        with patch("acr.pillar6_authority.approval.settings") as mock_settings:
            mock_settings.webhook_hmac_secret = secret
            sig1 = _sign_payload({"event": "a"})
            sig2 = _sign_payload({"event": "b"})
        assert sig1 != sig2


# ── Override ──────────────────────────────────────────────────────────────────


class TestBreakGlassOverride:
    async def test_override_sets_overridden_status(self, db: AsyncSession):
        record = await _make_approval(db)
        updated = await override(db, record.request_id, "security-lead", "Emergency response")
        await db.commit()

        assert updated.status == "overridden"
        assert updated.decision == "overridden"
        assert updated.decided_by == "security-lead"
        assert updated.decision_reason == "Emergency response"
        assert updated.decided_at is not None

    async def test_override_not_found_raises(self, db: AsyncSession):
        from acr.common.errors import ApprovalNotFoundError

        with pytest.raises(ApprovalNotFoundError):
            await override(db, "nonexistent-id", "ops", "reason")


# ── Expiry ────────────────────────────────────────────────────────────────────


class TestApprovalExpiry:
    async def test_expire_marks_past_due_approvals_as_timed_out(self, db: AsyncSession):
        record = await _make_approval(db, already_expired=True)
        count = await expire_timed_out_approvals(db)
        await db.commit()

        assert count >= 1
        await db.refresh(record)
        assert record.status == "timed_out"
        assert record.decision == "denied"
        assert record.decision_reason == "Approval SLA expired — auto-denied"

    async def test_expire_leaves_future_approvals_pending(self, db: AsyncSession):
        record = await _make_approval(db, already_expired=False)
        count = await expire_timed_out_approvals(db)
        await db.commit()

        assert count == 0
        await db.refresh(record)
        assert record.status == "pending"

    async def test_expire_ignores_already_approved(self, db: AsyncSession):
        record = await _make_approval(db, status="approved", already_expired=True)
        count = await expire_timed_out_approvals(db)
        await db.commit()

        # Approved record is not pending — should not be touched
        assert count == 0
        await db.refresh(record)
        assert record.status == "approved"

    async def test_expire_multiple_returns_correct_count(self, db: AsyncSession):
        r1 = await _make_approval(db, already_expired=True, agent_id="a1")
        r2 = await _make_approval(db, already_expired=True, agent_id="a2")
        count = await expire_timed_out_approvals(db)
        await db.commit()

        assert count == 2
        await db.refresh(r1)
        await db.refresh(r2)
        assert r1.status == r2.status == "timed_out"


# ── Webhook ───────────────────────────────────────────────────────────────────


class TestApprovalWebhook:
    async def test_create_approval_fires_webhook_when_url_set(self, db: AsyncSession):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("acr.pillar6_authority.approval.settings") as mock_settings:
            mock_settings.webhook_url = "http://hooks.example.com/acr"
            mock_settings.webhook_hmac_secret = "webhook-secret"
            with patch(
                "acr.pillar6_authority.approval.httpx.AsyncClient", return_value=mock_client
            ):
                record = await create_approval_request(
                    db,
                    correlation_id="corr-wh-test",
                    agent_id="webhook-agent",
                    tool_name="issue_refund",
                    parameters={"amount": 500},
                    description="Big refund",
                    approval_queue="finance",
                    sla_minutes=240,
                )
        await db.commit()

        mock_client.post.assert_awaited_once()
        call_kwargs = mock_client.post.call_args
        headers = call_kwargs.kwargs.get("headers", {})
        assert "X-ACR-Signature" in headers
        assert call_kwargs.kwargs["json"]["request_id"] == record.request_id

    async def test_create_approval_webhook_failure_does_not_raise(self, db: AsyncSession):
        """Webhook failure is fire-and-forget — the approval should still be created."""
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(side_effect=Exception("webhook server down"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("acr.pillar6_authority.approval.settings") as mock_settings:
            mock_settings.webhook_url = "http://hooks.example.com/acr"
            mock_settings.webhook_hmac_secret = ""
            with patch(
                "acr.pillar6_authority.approval.httpx.AsyncClient", return_value=mock_client
            ):
                record = await create_approval_request(
                    db,
                    correlation_id="corr-wh-fail",
                    agent_id="wh-fail-agent",
                    tool_name="issue_refund",
                    parameters={"amount": 100},
                    description=None,
                    approval_queue="default",
                    sla_minutes=60,
                )
        await db.commit()

        # Record should exist even though webhook threw
        assert record.request_id.startswith("apr-")

    async def test_create_approval_no_webhook_when_url_empty(self, db: AsyncSession):
        mock_client = AsyncMock()

        with patch("acr.pillar6_authority.approval.settings") as mock_settings:
            mock_settings.webhook_url = ""
            mock_settings.webhook_hmac_secret = ""
            with patch(
                "acr.pillar6_authority.approval.httpx.AsyncClient", return_value=mock_client
            ):
                record = await create_approval_request(
                    db,
                    correlation_id="corr-no-wh",
                    agent_id="no-wh-agent",
                    tool_name="query_db",
                    parameters={},
                    description=None,
                    approval_queue="default",
                    sla_minutes=0,
                )
        await db.commit()

        mock_client.__aenter__.assert_not_called()
        assert record.status == "pending"
        assert record.expires_at is None
