"""WS4 integrations tests: outbox, Slack, Teams, ServiceNow, Sentinel.

Slack is contract-tested against a mocked Web API (httpx MockTransport)
and fabricated signed callbacks. Teams / ServiceNow / Sentinel are
UNVERIFIED integrations: these tests assert request shape, auth, and
error handling against mocks only — no live tenant/instance/workspace
is touched anywhere in this file.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from datetime import UTC, timedelta
from urllib.parse import urlencode

import httpx
import pytest_asyncio
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from acr.common.time import utcnow
from acr.config import settings, slack_approver_map, teams_approver_map
from acr.db.models import (
    ApprovalRequestRecord,
    ExecutionReceiptRecord,
    IntegrationDeliveryAttemptRecord,
    IntegrationOutboxRecord,
)
from acr.integrations import slack as slack_mod
from acr.integrations import teams as teams_mod
from acr.integrations.outbox import process_outbox_once
from acr.pillar6_authority.approval import create_approval_request, expire_timed_out_approvals

SLACK_SECRET = "test-signing-secret"
SLACK_USER = "U0123ABC"
OPERATOR = "alice@example.com"


# ── Fixtures / helpers ───────────────────────────────────────────────────────


@pytest_asyncio.fixture(autouse=True)
async def _integrations_settings():
    """Reset every integration setting around each test."""
    keys = [
        "slack_enabled",
        "slack_bot_token",
        "slack_signing_secret",
        "slack_approvals_channel",
        "slack_alerts_channel",
        "slack_approver_map_json",
        "teams_enabled",
        "teams_webhook_url",
        "teams_callback_secret",
        "teams_callback_base_url",
        "teams_approver_map_json",
        "servicenow_enabled",
        "servicenow_instance_url",
        "servicenow_username",
        "servicenow_password",
        "servicenow_incident_on_deny",
        "sentinel_enabled",
        "sentinel_dce_endpoint",
        "sentinel_dcr_immutable_id",
        "sentinel_stream_name",
        "sentinel_tenant_id",
        "sentinel_client_id",
        "sentinel_client_secret",
        "integrations_outbox_max_attempts",
        "execute_allowed_actions",
    ]
    saved = {k: getattr(settings, k) for k in keys}
    yield
    for k, v in saved.items():
        setattr(settings, k, v)
    slack_approver_map.cache_clear()
    teams_approver_map.cache_clear()


def enable_slack() -> None:
    settings.slack_enabled = True
    settings.slack_bot_token = "xoxb-test"
    settings.slack_signing_secret = SLACK_SECRET
    settings.slack_approvals_channel = "C-APPROVE"
    settings.slack_alerts_channel = "C-ALERT"
    settings.slack_approver_map_json = json.dumps({SLACK_USER: OPERATOR})
    slack_approver_map.cache_clear()


async def make_approval(db: AsyncSession, agent_id: str, **kwargs) -> ApprovalRequestRecord:
    record = await create_approval_request(
        db,
        correlation_id=kwargs.pop("correlation_id", "corr-ws4-1"),
        agent_id=agent_id,
        tool_name=kwargs.pop("tool_name", "issue_refund"),
        parameters=kwargs.pop("parameters", {"customer_id": "C-001", "amount_usd": 25}),
        description=kwargs.pop("description", "Refund a customer"),
        approval_queue="default",
        sla_minutes=kwargs.pop("sla_minutes", 240),
    )
    await db.commit()
    await db.refresh(record)
    return record


async def outbox_rows(db: AsyncSession, **filters) -> list[IntegrationOutboxRecord]:
    query = select(IntegrationOutboxRecord)
    for key, value in filters.items():
        query = query.where(getattr(IntegrationOutboxRecord, key) == value)
    result = await db.execute(query.order_by(IntegrationOutboxRecord.created_at.asc()))
    return list(result.scalars().all())


def mock_client(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def slack_ok_handler(calls: list):
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        calls.append((request.url.path, body, dict(request.headers)))
        if request.url.path.endswith("chat.postMessage"):
            return httpx.Response(
                200, json={"ok": True, "ts": "1700.001", "channel": body["channel"]}
            )
        if request.url.path.endswith("chat.update"):
            return httpx.Response(200, json={"ok": True})
        return httpx.Response(404, json={"ok": False, "error": "unknown_method"})

    return handler


def sign_slack(raw_body: bytes, secret: str = SLACK_SECRET, timestamp: int | None = None) -> dict:
    ts = str(int(time.time()) if timestamp is None else timestamp)
    base = f"v0:{ts}:".encode() + raw_body
    sig = "v0=" + hmac.new(secret.encode(), base, hashlib.sha256).hexdigest()
    return {"x-slack-request-timestamp": ts, "x-slack-signature": sig}


def slack_callback_body(user_id: str, action_id: str, request_id: str) -> bytes:
    payload = {
        "type": "block_actions",
        "user": {"id": user_id},
        "channel": {"id": "C-APPROVE"},
        "message": {"ts": "1700.001"},
        "actions": [{"action_id": action_id, "value": request_id}],
    }
    return urlencode({"payload": json.dumps(payload)}).encode()


# ── All integrations off: byte-identical behavior ────────────────────────────


class TestAllOff:
    async def test_approval_creation_writes_no_outbox_rows(
        self, db: AsyncSession, sample_agent
    ) -> None:
        await make_approval(db, sample_agent.agent_id)
        assert await outbox_rows(db) == []

    async def test_evaluate_writes_no_outbox_rows(
        self, async_client, db: AsyncSession, sample_agent
    ) -> None:
        resp = await async_client.post(
            "/acr/evaluate",
            json={
                "agent_id": sample_agent.agent_id,
                "action": {"tool_name": "query_customer_db", "parameters": {"customer_id": "C-1"}},
                "context": {"session_id": "s", "actions_this_minute": 1, "hourly_spend_usd": 0.1},
            },
        )
        assert resp.status_code == 200
        assert await outbox_rows(db) == []


# ── Slack: outbound message shape + delivery ─────────────────────────────────


class TestSlackOutbound:
    async def test_approval_message_posted_with_block_kit_shape(
        self, db: AsyncSession, sample_agent
    ) -> None:
        enable_slack()
        record = await make_approval(db, sample_agent.agent_id)
        rows = await outbox_rows(db, integration="slack", event_type="approval_requested")
        assert len(rows) == 1
        assert rows[0].reference == record.request_id

        calls: list = []
        async with mock_client(slack_ok_handler(calls)) as client:
            counts = await process_outbox_once(db, client)
        assert counts["delivered"] == 1
        assert len(calls) == 1
        path, body, headers = calls[0]
        assert path == "/api/chat.postMessage"
        assert headers["authorization"] == "Bearer xoxb-test"
        assert body["channel"] == "C-APPROVE"
        blocks = body["blocks"]
        actions = [b for b in blocks if b["type"] == "actions"]
        assert len(actions) == 1
        buttons = {el["action_id"]: el for el in actions[0]["elements"]}
        assert set(buttons) == {"acr_approve", "acr_deny"}
        assert buttons["acr_approve"]["value"] == record.request_id
        # Parameters are never posted to chat.
        assert "C-001" not in json.dumps(body)
        row = (await outbox_rows(db, integration="slack"))[0]
        assert row.status == "delivered"
        assert row.delivery_ref == {"channel": "C-APPROVE", "ts": "1700.001"}
        attempts = (
            (
                await db.execute(
                    select(IntegrationDeliveryAttemptRecord).where(
                        IntegrationDeliveryAttemptRecord.outbox_id == row.id
                    )
                )
            )
            .scalars()
            .all()
        )
        assert len(attempts) == 1 and attempts[0].result == "success"

    async def test_decision_update_rerenders_original_message(
        self, db: AsyncSession, sample_agent, async_client
    ) -> None:
        enable_slack()
        record = await make_approval(db, sample_agent.agent_id)
        calls: list = []
        async with mock_client(slack_ok_handler(calls)) as client:
            await process_outbox_once(db, client)
            # Decide through the real approvals API.
            resp = await async_client.post(
                f"/acr/approvals/{record.request_id}/approve", json={"reason": "ok"}
            )
            assert resp.status_code == 200
            counts = await process_outbox_once(db, client)
        assert counts["delivered"] == 1
        updates = [c for c in calls if c[0].endswith("chat.update")]
        assert len(updates) == 1
        _, body, _ = updates[0]
        assert body["channel"] == "C-APPROVE" and body["ts"] == "1700.001"
        rendered = json.dumps(body["blocks"])
        assert "Approved" in rendered and "test-operator" in rendered


# ── Slack: inbound callbacks ─────────────────────────────────────────────────


class TestSlackCallbacks:
    async def test_signed_approve_decides_through_approvals_path(
        self, db: AsyncSession, sample_agent, async_client
    ) -> None:
        enable_slack()
        record = await make_approval(db, sample_agent.agent_id)
        raw = slack_callback_body(SLACK_USER, "acr_approve", record.request_id)
        resp = await async_client.post(
            "/acr/integrations/slack/actions",
            content=raw,
            headers={"content-type": "application/x-www-form-urlencoded", **sign_slack(raw)},
        )
        assert resp.status_code == 200
        await db.refresh(record)
        assert record.status == "approved"
        assert record.decided_by == OPERATOR  # mapped operator identity
        assert record.decided_channel == "slack"
        assert record.chat_actor_id == SLACK_USER  # transport identity kept

    async def test_signed_deny(self, db: AsyncSession, sample_agent, async_client) -> None:
        enable_slack()
        record = await make_approval(db, sample_agent.agent_id)
        raw = slack_callback_body(SLACK_USER, "acr_deny", record.request_id)
        resp = await async_client.post(
            "/acr/integrations/slack/actions",
            content=raw,
            headers={"content-type": "application/x-www-form-urlencoded", **sign_slack(raw)},
        )
        assert resp.status_code == 200
        await db.refresh(record)
        assert record.status == "denied" and record.decided_by == OPERATOR

    async def test_forged_signature_rejected_no_state_change(
        self, db: AsyncSession, sample_agent, async_client
    ) -> None:
        enable_slack()
        record = await make_approval(db, sample_agent.agent_id)
        raw = slack_callback_body(SLACK_USER, "acr_approve", record.request_id)
        resp = await async_client.post(
            "/acr/integrations/slack/actions",
            content=raw,
            headers={
                "content-type": "application/x-www-form-urlencoded",
                **sign_slack(raw, secret="attacker-secret"),
            },
        )
        assert resp.status_code == 401
        await db.refresh(record)
        assert record.status == "pending" and record.decided_by is None

    async def test_unsigned_and_stale_callbacks_rejected(
        self, db: AsyncSession, sample_agent, async_client
    ) -> None:
        enable_slack()
        record = await make_approval(db, sample_agent.agent_id)
        raw = slack_callback_body(SLACK_USER, "acr_approve", record.request_id)
        resp = await async_client.post(
            "/acr/integrations/slack/actions",
            content=raw,
            headers={"content-type": "application/x-www-form-urlencoded"},
        )
        assert resp.status_code == 401
        stale = int(time.time()) - 3600
        resp = await async_client.post(
            "/acr/integrations/slack/actions",
            content=raw,
            headers={
                "content-type": "application/x-www-form-urlencoded",
                **sign_slack(raw, timestamp=stale),
            },
        )
        assert resp.status_code == 401
        await db.refresh(record)
        assert record.status == "pending"

    async def test_unmapped_user_cannot_approve(
        self, db: AsyncSession, sample_agent, async_client
    ) -> None:
        enable_slack()
        record = await make_approval(db, sample_agent.agent_id)
        raw = slack_callback_body("U-UNMAPPED", "acr_approve", record.request_id)
        resp = await async_client.post(
            "/acr/integrations/slack/actions",
            content=raw,
            headers={"content-type": "application/x-www-form-urlencoded", **sign_slack(raw)},
        )
        assert resp.status_code == 200
        assert "not mapped" in resp.json()["text"]
        await db.refresh(record)
        assert record.status == "pending" and record.decided_by is None

    async def test_double_action_second_click_is_rejected(
        self, db: AsyncSession, sample_agent, async_client
    ) -> None:
        enable_slack()
        record = await make_approval(db, sample_agent.agent_id)
        raw = slack_callback_body(SLACK_USER, "acr_approve", record.request_id)
        headers = {"content-type": "application/x-www-form-urlencoded", **sign_slack(raw)}
        first = await async_client.post(
            "/acr/integrations/slack/actions", content=raw, headers=headers
        )
        assert first.status_code == 200
        second = await async_client.post(
            "/acr/integrations/slack/actions", content=raw, headers=headers
        )
        assert second.status_code == 200  # rendered truthfully, not re-decided
        await db.refresh(record)
        assert record.status == "approved"
        decided_rows = await outbox_rows(db, integration="slack", event_type="approval_decided")
        assert len(decided_rows) == 1  # exactly one decision event

    async def test_tampered_payload_binding_rejects_chat_approval(
        self, db: AsyncSession, sample_agent, async_client
    ) -> None:
        """Payload-hash binding (resumption.check_request) applies to chat
        decisions identically: tamper after issuance and approval fails."""
        enable_slack()
        record = await make_approval(db, sample_agent.agent_id)
        record.parameters = {"customer_id": "C-999", "amount_usd": 99999}
        await db.commit()
        raw = slack_callback_body(SLACK_USER, "acr_approve", record.request_id)
        resp = await async_client.post(
            "/acr/integrations/slack/actions",
            content=raw,
            headers={"content-type": "application/x-www-form-urlencoded", **sign_slack(raw)},
        )
        assert resp.status_code == 200
        await db.refresh(record)
        assert record.status == "pending" and record.decided_by is None

    async def test_expired_approval_renders_expired(
        self, db: AsyncSession, sample_agent, async_client
    ) -> None:
        enable_slack()
        record = await make_approval(db, sample_agent.agent_id)
        calls: list = []
        async with mock_client(slack_ok_handler(calls)) as client:
            await process_outbox_once(db, client)  # post the request message
            record.expires_at = utcnow() - timedelta(minutes=1)
            await db.commit()
            expired = await expire_timed_out_approvals(db)
            await db.commit()
            assert expired == 1
            await process_outbox_once(db, client)  # deliver the update
        updates = [c for c in calls if c[0].endswith("chat.update")]
        assert len(updates) == 1
        assert "Expired" in json.dumps(updates[0][1]["blocks"])
        await db.refresh(record)
        assert record.status == "timed_out"

    async def test_chat_approval_executes_with_claim_once_receipt(
        self, db: AsyncSession, sample_agent, async_client
    ) -> None:
        """With execution enabled, a Slack approval flows into the same
        claim-once execution path as the API: one receipt, one dispatch."""
        from unittest.mock import AsyncMock, patch

        enable_slack()
        settings.execute_allowed_actions = True
        record = await make_approval(db, sample_agent.agent_id, authorization_snapshot=None)
        execute_mock = AsyncMock(return_value={"dispatched": True})
        with (
            patch("acr.pillar6_authority.approval.execute_action", execute_mock),
            patch(
                "acr.pillar6_authority.approval.adjust_authoritative_spend",
                new_callable=AsyncMock,
            ),
            patch(
                "acr.pillar6_authority.resumption.revalidate",
                new_callable=AsyncMock,
                return_value=({"snapshot": True}, 0.0),
            ),
            patch(
                "acr.pillar6_authority.resumption.check_dispatch_boundary",
                new_callable=AsyncMock,
            ),
        ):
            raw = slack_callback_body(SLACK_USER, "acr_approve", record.request_id)
            resp = await async_client.post(
                "/acr/integrations/slack/actions",
                content=raw,
                headers={"content-type": "application/x-www-form-urlencoded", **sign_slack(raw)},
            )
            assert resp.status_code == 200
            await db.refresh(record)
            assert record.status == "approved"
            receipts = (
                (
                    await db.execute(
                        select(ExecutionReceiptRecord).where(
                            ExecutionReceiptRecord.approval_request_id == record.request_id
                        )
                    )
                )
                .scalars()
                .all()
            )
            assert len(receipts) == 1
            assert receipts[0].state == "succeeded"
            assert execute_mock.await_count == 1


# ── Slack alerts: containment + killswitch ───────────────────────────────────


class TestSlackAlerts:
    async def test_containment_posts_alert(self, db: AsyncSession, sample_agent) -> None:
        from acr.pillar5_containment.graduated import apply_graduated_response

        enable_slack()
        action = await apply_graduated_response(
            db, sample_agent.agent_id, drift_score=0.80, correlation_id="corr-contain-1"
        )
        await db.commit()
        assert action is not None and action.action_type == "restrict"
        rows = await outbox_rows(db, integration="slack", event_type="containment_action")
        assert len(rows) == 1
        calls: list = []
        async with mock_client(slack_ok_handler(calls)) as client:
            counts = await process_outbox_once(db, client)
        assert counts["delivered"] == 1
        _, body, _ = calls[0]
        assert body["channel"] == "C-ALERT"
        assert "restrict" in json.dumps(body)

    async def test_killswitch_activation_posts_alert(
        self, db: AsyncSession, sample_agent, async_client
    ) -> None:
        from unittest.mock import AsyncMock, patch

        from acr.pillar5_containment.models import KillSwitchState

        enable_slack()
        state = KillSwitchState(
            agent_id=sample_agent.agent_id, is_killed=True, reason="test", operator_id="op"
        )
        with patch(
            "acr.pillar5_containment.router.kill_agent",
            new_callable=AsyncMock,
            return_value=state,
        ):
            resp = await async_client.post(
                "/acr/containment/kill",
                json={"agent_id": sample_agent.agent_id, "reason": "test kill"},
            )
        assert resp.status_code == 200
        rows = await outbox_rows(db, integration="slack", event_type="killswitch_activated")
        assert len(rows) == 1
        calls: list = []
        async with mock_client(slack_ok_handler(calls)) as client:
            await process_outbox_once(db, client)
        assert calls and calls[0][1]["channel"] == "C-ALERT"


# ── Outbox mechanics: retry, dead-letter, evidence ───────────────────────────


class TestOutboxMechanics:
    async def test_failure_retries_then_dead_letters_with_attempt_records(
        self, db: AsyncSession, sample_agent
    ) -> None:
        enable_slack()
        settings.integrations_outbox_max_attempts = 2
        await make_approval(db, sample_agent.agent_id)

        def failing(request: httpx.Request) -> httpx.Response:
            return httpx.Response(500, json={"ok": False, "error": "server_error"})

        async with mock_client(failing) as client:
            counts = await process_outbox_once(db, client)
            assert counts["failed"] == 1
            row = (await outbox_rows(db, integration="slack"))[0]
            assert row.status == "pending" and row.attempts == 1
            next_at = row.next_attempt_at
            if next_at.tzinfo is None:  # SQLite driver drops tz; DB contract is UTC
                next_at = next_at.replace(tzinfo=UTC)
            assert next_at > utcnow()  # backoff scheduled
            # Make it due again and fail the final attempt.
            row.next_attempt_at = utcnow() - timedelta(seconds=1)
            await db.commit()
            counts = await process_outbox_once(db, client)
            assert counts["dead_letter"] == 1
        row = (await outbox_rows(db, integration="slack"))[0]
        assert row.status == "dead_letter" and row.attempts == 2
        assert row.last_error and "500" in row.last_error
        attempts = (
            (
                await db.execute(
                    select(IntegrationDeliveryAttemptRecord).where(
                        IntegrationDeliveryAttemptRecord.outbox_id == row.id
                    )
                )
            )
            .scalars()
            .all()
        )
        assert len(attempts) == 2
        assert all(a.result == "failure" and a.http_status == 500 for a in attempts)

    async def test_slack_api_error_is_recorded_and_retried(
        self, db: AsyncSession, sample_agent
    ) -> None:
        enable_slack()
        await make_approval(db, sample_agent.agent_id)

        def api_error(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"ok": False, "error": "channel_not_found"})

        async with mock_client(api_error) as client:
            counts = await process_outbox_once(db, client)
        assert counts["failed"] == 1
        row = (await outbox_rows(db, integration="slack"))[0]
        assert "channel_not_found" in (row.last_error or "")


# ── Teams (UNVERIFIED — mock contract tests only) ────────────────────────────

TEAMS_SECRET = "teams-callback-secret"
TEAMS_USER = "29:teams-user-1"
TEAMS_OPERATOR = "bob@example.com"


def enable_teams() -> None:
    settings.teams_enabled = True
    settings.teams_webhook_url = "https://tenant.webhook.office.com/wh/abc"
    settings.teams_callback_secret = TEAMS_SECRET
    settings.teams_callback_base_url = "https://acr.example.com"
    settings.teams_approver_map_json = json.dumps({TEAMS_USER: TEAMS_OPERATOR})
    teams_approver_map.cache_clear()


class TestTeams:
    async def test_approval_card_shape_and_signed_actions(
        self, db: AsyncSession, sample_agent
    ) -> None:
        enable_teams()
        record = await make_approval(db, sample_agent.agent_id)
        rows = await outbox_rows(db, integration="teams", event_type="approval_requested")
        assert len(rows) == 1
        calls: list = []

        def handler(request: httpx.Request) -> httpx.Response:
            calls.append((str(request.url), json.loads(request.content)))
            return httpx.Response(200, text="1")

        async with mock_client(handler) as client:
            counts = await process_outbox_once(db, client)
        assert counts["delivered"] == 1
        url, body = calls[0]
        assert url == settings.teams_webhook_url
        assert body["type"] == "message"
        attachment = body["attachments"][0]
        assert attachment["contentType"] == "application/vnd.microsoft.card.adaptive"
        card = attachment["content"]
        assert card["type"] == "AdaptiveCard"
        actions = {a["title"]: a for a in card["actions"]}
        assert set(actions) == {"Approve", "Deny"}
        for title, action_name in (("Approve", "approve"), ("Deny", "deny")):
            action = actions[title]
            assert action["type"] == "Action.Http"
            assert action["url"].endswith("/acr/integrations/teams/actions")
            posted = json.loads(action["body"])
            assert posted["request_id"] == record.request_id
            assert posted["action"] == action_name
            assert teams_mod.verify_action_token(
                posted["acr_token"], record.request_id, action_name
            )

    async def test_callback_with_valid_token_decides(
        self, db: AsyncSession, sample_agent, async_client
    ) -> None:
        enable_teams()
        record = await make_approval(db, sample_agent.agent_id)
        body = {
            "request_id": record.request_id,
            "action": "approve",
            "acr_token": teams_mod.sign_action_token(record.request_id, "approve"),
            "from": {"id": TEAMS_USER},
        }
        resp = await async_client.post("/acr/integrations/teams/actions", json=body)
        assert resp.status_code == 200
        await db.refresh(record)
        assert record.status == "approved"
        assert record.decided_by == TEAMS_OPERATOR
        assert record.decided_channel == "teams"
        assert record.chat_actor_id == TEAMS_USER

    async def test_callback_bad_token_rejected(
        self, db: AsyncSession, sample_agent, async_client
    ) -> None:
        enable_teams()
        record = await make_approval(db, sample_agent.agent_id)
        body = {
            "request_id": record.request_id,
            "action": "approve",
            "acr_token": "123.forged",
            "from": {"id": TEAMS_USER},
        }
        resp = await async_client.post("/acr/integrations/teams/actions", json=body)
        assert resp.status_code == 401
        await db.refresh(record)
        assert record.status == "pending"

    async def test_callback_outgoing_webhook_hmac_scheme(
        self, db: AsyncSession, sample_agent, async_client
    ) -> None:
        enable_teams()
        # Outgoing-webhook keys are base64; use a base64 secret for this test.
        settings.teams_callback_secret = base64.b64encode(
            b"0123456789abcdef0123456789abcdef"
        ).decode()
        record = await make_approval(db, sample_agent.agent_id)
        raw = json.dumps(
            {"request_id": record.request_id, "action": "deny", "from": {"id": TEAMS_USER}}
        ).encode()
        digest = base64.b64encode(
            hmac.new(base64.b64decode(settings.teams_callback_secret), raw, hashlib.sha256).digest()
        ).decode()
        resp = await async_client.post(
            "/acr/integrations/teams/actions",
            content=raw,
            headers={"content-type": "application/json", "authorization": f"HMAC {digest}"},
        )
        assert resp.status_code == 200
        await db.refresh(record)
        assert record.status == "denied" and record.decided_channel == "teams"

    async def test_callback_unmapped_user_changes_nothing(
        self, db: AsyncSession, sample_agent, async_client
    ) -> None:
        enable_teams()
        record = await make_approval(db, sample_agent.agent_id)
        body = {
            "request_id": record.request_id,
            "action": "approve",
            "acr_token": teams_mod.sign_action_token(record.request_id, "approve"),
            "from": {"id": "29:stranger"},
        }
        resp = await async_client.post("/acr/integrations/teams/actions", json=body)
        assert resp.status_code == 200
        await db.refresh(record)
        assert record.status == "pending" and record.decided_by is None


# ── ServiceNow (UNVERIFIED — mock contract tests only) ───────────────────────


def enable_servicenow() -> None:
    settings.servicenow_enabled = True
    settings.servicenow_instance_url = "https://example.service-now.com"
    settings.servicenow_username = "acr.integration"
    settings.servicenow_password = "test-password"


class TestServiceNow:
    async def test_containment_creates_incident_with_correlation(
        self, db: AsyncSession, sample_agent
    ) -> None:
        from acr.pillar5_containment.graduated import apply_graduated_response

        enable_servicenow()
        await apply_graduated_response(
            db, sample_agent.agent_id, drift_score=0.80, correlation_id="corr-snow-1"
        )
        await db.commit()
        rows = await outbox_rows(db, integration="servicenow", event_type="containment_action")
        assert len(rows) == 1
        calls: list = []

        def handler(request: httpx.Request) -> httpx.Response:
            calls.append((str(request.url), json.loads(request.content), dict(request.headers)))
            return httpx.Response(201, json={"result": {"sys_id": "sys-1", "number": "INC0010001"}})

        async with mock_client(handler) as client:
            counts = await process_outbox_once(db, client)
        assert counts["delivered"] == 1
        url, body, headers = calls[0]
        assert url == "https://example.service-now.com/api/now/table/incident"
        assert body["correlation_id"] == "corr-snow-1"
        assert "corr-snow-1" in body["work_notes"]
        expected_auth = "Basic " + base64.b64encode(b"acr.integration:test-password").decode()
        assert headers["authorization"] == expected_auth
        row = (await outbox_rows(db, integration="servicenow"))[0]
        assert row.delivery_ref == {"sys_id": "sys-1", "number": "INC0010001"}

    async def test_deny_incident_only_when_configured(self, db: AsyncSession, sample_agent) -> None:
        from acr.pillar6_authority.approval import deny

        enable_servicenow()
        record = await make_approval(db, sample_agent.agent_id)
        await deny(db, record.request_id, "carol@example.com", "not justified")
        await db.commit()
        assert await outbox_rows(db, integration="servicenow") == []

        settings.servicenow_incident_on_deny = True
        record2 = await make_approval(db, sample_agent.agent_id, correlation_id="corr-ws4-2")
        await deny(db, record2.request_id, "carol@example.com", "not justified")
        await db.commit()
        rows = await outbox_rows(db, integration="servicenow", event_type="approval_decided")
        assert len(rows) == 1
        assert rows[0].payload["correlation_id"] == "corr-ws4-2"

    async def test_servicenow_failure_never_affects_decision(
        self, db: AsyncSession, sample_agent
    ) -> None:
        from acr.pillar6_authority.approval import deny

        enable_servicenow()
        settings.servicenow_incident_on_deny = True
        record = await make_approval(db, sample_agent.agent_id)
        decided = await deny(db, record.request_id, "carol@example.com", "no")
        await db.commit()
        assert decided.status == "denied"

        def failing(request: httpx.Request) -> httpx.Response:
            return httpx.Response(503, json={})

        async with mock_client(failing) as client:
            counts = await process_outbox_once(db, client)
        assert counts["failed"] == 1
        await db.refresh(record)
        assert record.status == "denied"  # decision untouched by the outage


# ── Sentinel (UNVERIFIED — mock contract tests only) ─────────────────────────


def enable_sentinel() -> None:
    settings.sentinel_enabled = True
    settings.sentinel_dce_endpoint = "https://dce.eastus.ingest.monitor.azure.com"
    settings.sentinel_dcr_immutable_id = "dcr-123"
    settings.sentinel_tenant_id = "tenant-1"
    settings.sentinel_client_id = "client-1"
    settings.sentinel_client_secret = "test-secret"


def sentinel_handler(calls: list, *, fail_ingest: bool = False):
    def handler(request: httpx.Request) -> httpx.Response:
        calls.append((str(request.url), request))
        if "login.microsoftonline.com" in str(request.url):
            return httpx.Response(200, json={"access_token": "token-abc", "expires_in": 3600})
        if fail_ingest:
            return httpx.Response(500, json={})
        return httpx.Response(204)

    return handler


class TestSentinel:
    async def test_evaluate_enqueues_and_worker_exports_recorded_decisions(
        self, async_client, db: AsyncSession, sample_agent
    ) -> None:
        enable_sentinel()
        resp = await async_client.post(
            "/acr/evaluate",
            json={
                "agent_id": sample_agent.agent_id,
                "action": {"tool_name": "query_customer_db", "parameters": {"customer_id": "C-1"}},
                "context": {"session_id": "s", "actions_this_minute": 1, "hourly_spend_usd": 0.1},
            },
        )
        # The decision is returned before (and regardless of) any export.
        assert resp.status_code == 200 and resp.json()["decision"] == "allow"
        rows = await outbox_rows(db, integration="sentinel", event_type="decision_export")
        assert len(rows) == 1
        record_payload = rows[0].payload["record"]
        assert record_payload["AgentId"] == sample_agent.agent_id
        assert record_payload["Decision"] == "allow"
        assert record_payload["CorrelationId"] == resp.json()["correlation_id"]

        calls: list = []
        async with mock_client(sentinel_handler(calls)) as client:
            counts = await process_outbox_once(db, client)
        assert counts["delivered"] == 1
        token_calls = [c for c in calls if "login.microsoftonline.com" in c[0]]
        ingest_calls = [c for c in calls if "dataCollectionRules" in c[0]]
        assert len(token_calls) == 1 and len(ingest_calls) == 1
        ingest_url, ingest_request = ingest_calls[0]
        assert "dcr-123" in ingest_url and "Custom-ACRDecisions_CL" in ingest_url
        assert "api-version=2023-01-01" in ingest_url
        assert ingest_request.headers["authorization"] == "Bearer token-abc"
        sent = json.loads(ingest_request.content)
        assert isinstance(sent, list) and sent[0]["Decision"] == "allow"

    async def test_failed_export_retries_and_dead_letters_decisions_unaffected(
        self, async_client, db: AsyncSession, sample_agent
    ) -> None:
        enable_sentinel()
        settings.integrations_outbox_max_attempts = 1
        resp = await async_client.post(
            "/acr/evaluate",
            json={
                "agent_id": sample_agent.agent_id,
                "action": {"tool_name": "query_customer_db", "parameters": {"customer_id": "C-1"}},
                "context": {"session_id": "s", "actions_this_minute": 1, "hourly_spend_usd": 0.1},
            },
        )
        assert resp.status_code == 200  # enforcement answered despite export state
        calls: list = []
        async with mock_client(sentinel_handler(calls, fail_ingest=True)) as client:
            counts = await process_outbox_once(db, client)
        assert counts["dead_letter"] == 1
        row = (await outbox_rows(db, integration="sentinel"))[0]
        assert row.status == "dead_letter"


# ── Edge coverage: callback auth edges, token/HMAC units, misc senders ──────


class TestCallbackEdges:
    async def test_slack_disabled_callback_404(self, async_client) -> None:
        resp = await async_client.post("/acr/integrations/slack/actions", content=b"payload={}")
        assert resp.status_code == 404

    async def test_teams_disabled_callback_404(self, async_client) -> None:
        resp = await async_client.post("/acr/integrations/teams/actions", json={})
        assert resp.status_code == 404

    async def test_slack_missing_payload_400(self, async_client) -> None:
        enable_slack()
        raw = urlencode({"not_payload": "x"}).encode()
        resp = await async_client.post(
            "/acr/integrations/slack/actions",
            content=raw,
            headers={"content-type": "application/x-www-form-urlencoded", **sign_slack(raw)},
        )
        assert resp.status_code == 400

    async def test_slack_unknown_action_is_noop(
        self, db: AsyncSession, sample_agent, async_client
    ) -> None:
        enable_slack()
        record = await make_approval(db, sample_agent.agent_id)
        payload = {
            "type": "block_actions",
            "user": {"id": SLACK_USER},
            "actions": [{"action_id": "some_other_button", "value": record.request_id}],
        }
        raw = urlencode({"payload": json.dumps(payload)}).encode()
        resp = await async_client.post(
            "/acr/integrations/slack/actions",
            content=raw,
            headers={"content-type": "application/x-www-form-urlencoded", **sign_slack(raw)},
        )
        assert resp.status_code == 200
        await db.refresh(record)
        assert record.status == "pending"

    async def test_teams_malformed_json_400(self, async_client) -> None:
        enable_teams()
        resp = await async_client.post(
            "/acr/integrations/teams/actions",
            content=b"{not json",
            headers={"content-type": "application/json"},
        )
        assert resp.status_code == 400

    async def test_decide_from_chat_missing_approval(self, db: AsyncSession) -> None:
        from acr.integrations.chat_decision import decide_from_chat

        outcome = await decide_from_chat(
            db,
            request_id="apr-does-not-exist",
            action="approve",
            channel="slack",
            chat_actor_id="U1",
            operator_subject="alice@example.com",
        )
        assert outcome.record is None and outcome.error

    def test_slack_signature_units(self) -> None:
        raw = b"payload=abc"
        headers = sign_slack(raw)
        assert slack_mod.verify_signature(
            SLACK_SECRET, headers["x-slack-request-timestamp"], raw, headers["x-slack-signature"]
        )
        assert not slack_mod.verify_signature(SLACK_SECRET, None, raw, headers["x-slack-signature"])
        assert not slack_mod.verify_signature(SLACK_SECRET, "not-a-ts", raw, "v0=x")
        assert not slack_mod.verify_signature("", headers["x-slack-request-timestamp"], raw, "v0=x")

    def test_teams_token_and_hmac_units(self) -> None:
        settings.teams_callback_secret = TEAMS_SECRET
        token = teams_mod.sign_action_token("apr-1", "approve")
        assert teams_mod.verify_action_token(token, "apr-1", "approve")
        assert not teams_mod.verify_action_token(token, "apr-1", "deny")
        assert not teams_mod.verify_action_token(token, "apr-2", "approve")
        assert not teams_mod.verify_action_token(None, "apr-1", "approve")
        assert not teams_mod.verify_action_token("garbage", "apr-1", "approve")
        expired = teams_mod.sign_action_token("apr-1", "approve", now=int(time.time()) - 90000)
        assert not teams_mod.verify_action_token(expired, "apr-1", "approve")
        assert not teams_mod.verify_outgoing_hmac(b"{}", None)
        assert not teams_mod.verify_outgoing_hmac(b"{}", "Bearer abc")

    async def test_unknown_event_type_dead_letters_immediately(
        self, db: AsyncSession, sample_agent
    ) -> None:
        enable_slack()
        row = IntegrationOutboxRecord(
            integration="slack",
            event_type="bogus_event",
            reference="ref-1",
            target="C-APPROVE",
            payload={},
        )
        db.add(row)
        await db.commit()
        async with mock_client(slack_ok_handler([])) as client:
            counts = await process_outbox_once(db, client)
        assert counts["dead_letter"] == 1

    async def test_teams_containment_alert_and_killswitch_all_integrations(
        self, db: AsyncSession, sample_agent
    ) -> None:
        from acr.integrations.events import notify_killswitch
        from acr.pillar5_containment.graduated import apply_graduated_response

        enable_teams()
        enable_servicenow()
        await apply_graduated_response(
            db, sample_agent.agent_id, drift_score=0.80, correlation_id="corr-multi-1"
        )
        await notify_killswitch(
            db, agent_id=sample_agent.agent_id, reason="manual", operator_id="op"
        )
        await db.commit()
        teams_rows = await outbox_rows(db, integration="teams")
        snow_rows = await outbox_rows(db, integration="servicenow")
        assert {r.event_type for r in teams_rows} == {"containment_action", "killswitch_activated"}
        assert {r.event_type for r in snow_rows} == {"containment_action", "killswitch_activated"}
        calls: list = []

        def handler(request: httpx.Request) -> httpx.Response:
            calls.append(str(request.url))
            if "service-now" in str(request.url):
                return httpx.Response(201, json={"result": {"sys_id": "s", "number": "INC1"}})
            return httpx.Response(200, text="1")

        async with mock_client(handler) as client:
            counts = await process_outbox_once(db, client)
        assert counts["delivered"] == 4
        assert sum("webhook.office.com" in u for u in calls) == 2
        assert sum("service-now" in u for u in calls) == 2
