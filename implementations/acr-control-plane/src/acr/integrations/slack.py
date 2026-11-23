"""Slack integration: approval messages, decision updates, alerts.

Outbound goes through the Slack Web API (chat.postMessage / chat.update)
from the outbox worker only — never from the evaluate hot path. Inbound
interactivity callbacks are signature-verified (v0 scheme) in
acr.integrations.router before any state can change, and decisions are
executed by the pillar 6 approvals API handlers (see chat_decision.py).

Verification status: contract-tested against a mocked Slack Web API and
fabricated signed callbacks. Live-workspace verification is an operator
smoke step after installing the app (docs/integrations.md checklist);
it is not claimed by the test suite.
"""

from __future__ import annotations

import hashlib
import hmac
import time
from datetime import UTC, datetime
from zoneinfo import ZoneInfo

import httpx
import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from acr.config import settings
from acr.db.models import ApprovalRequestRecord, IntegrationOutboxRecord
from acr.integrations.outbox import DeliveryError

logger = structlog.get_logger(__name__)

SLACK_API_BASE = "https://slack.com/api"
SIGNATURE_TOLERANCE_SECONDS = 300
_FATAL_SLACK_ERRORS = {"invalid_auth", "token_revoked", "account_inactive", "missing_scope"}
_EASTERN = ZoneInfo("America/New_York")


# ── Signature verification (inbound) ─────────────────────────────────────────


def verify_signature(
    signing_secret: str,
    timestamp: str | None,
    raw_body: bytes,
    signature: str | None,
    *,
    now: int | None = None,
    tolerance: int = SIGNATURE_TOLERANCE_SECONDS,
) -> bool:
    """Slack v0 signing scheme: "v0=" + HMAC_SHA256(secret, "v0:ts:body").

    Rejects missing pieces, stale timestamps (replay window), and any
    signature mismatch. Callers must pass the RAW request body.
    """
    if not signing_secret or not timestamp or not signature:
        return False
    try:
        ts = int(timestamp)
    except (TypeError, ValueError):
        return False
    current = int(time.time()) if now is None else now
    if abs(current - ts) > tolerance:
        return False
    base = f"v0:{timestamp}:".encode() + raw_body
    expected = "v0=" + hmac.new(signing_secret.encode(), base, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


# ── Message construction ─────────────────────────────────────────────────────


def _approval_blocks(payload: dict) -> list[dict]:
    fields = [
        {"type": "mrkdwn", "text": f"*Agent*\n{payload.get('agent_id', '?')}"},
        {"type": "mrkdwn", "text": f"*Tool*\n{payload.get('tool_name', '?')}"},
        {"type": "mrkdwn", "text": f"*Queue*\n{payload.get('approval_queue', 'default')}"},
        {"type": "mrkdwn", "text": f"*Risk tier*\n{payload.get('risk_tier', 'high')}"},
    ]
    blocks: list[dict] = [
        {"type": "header", "text": {"type": "plain_text", "text": "Approval required"}},
        {"type": "section", "fields": fields},
    ]
    if payload.get("description"):
        blocks.append(
            {"type": "section", "text": {"type": "mrkdwn", "text": str(payload["description"])}}
        )
    if payload.get("expires_at"):
        blocks.append(
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": f"Expires {payload['expires_at']} · Request `{payload.get('request_id', '')}` · Correlation `{payload.get('correlation_id', '')}`",
                    }
                ],
            }
        )
    blocks.append(
        {
            "type": "actions",
            "block_id": f"acr-approval-{payload.get('request_id', '')}",
            "elements": [
                {
                    "type": "button",
                    "style": "primary",
                    "text": {"type": "plain_text", "text": "Approve"},
                    "action_id": "acr_approve",
                    "value": payload.get("request_id", ""),
                },
                {
                    "type": "button",
                    "style": "danger",
                    "text": {"type": "plain_text", "text": "Deny"},
                    "action_id": "acr_deny",
                    "value": payload.get("request_id", ""),
                },
            ],
        }
    )
    return blocks


def _decided_when(value: datetime | None) -> tuple[str, str] | None:
    """(date, time) in America/New_York: ("Nov 23, 2026", "4:14 PM ET").

    Rendered for humans in the decided card — never the raw ISO string.
    Naive values (SQLite drops tz info) are read as UTC, the DB contract.
    """
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    local = value.astimezone(_EASTERN)
    date_part = f"{local.strftime('%b')} {local.day}, {local.year}"
    hour = local.hour % 12 or 12
    time_part = f"{hour}:{local.minute:02d} {local.strftime('%p')} ET"
    return date_part, time_part


def _decider_label(record: ApprovalRequestRecord) -> str:
    """Who decided, as the card should name them.

    A decision that arrived through Slack names the Slack user who
    clicked (a mention, so it renders as their profile); decisions from
    any other surface fall back to the operator subject.
    """
    if record.decided_channel == "slack" and record.chat_actor_id:
        return f"<@{record.chat_actor_id}>"
    return record.decided_by or "an operator"


def _decided_blocks(record: ApprovalRequestRecord) -> list[dict]:
    # Rendered from the record's CURRENT state at delivery time, so a
    # refresh after a conflicting click shows the truth: still pending
    # (possibly past its window), decided, or swept to timed_out.
    # Button-free by construction: the actions block is gone and the
    # card states the outcome, who decided, and when — in ET.
    if record.status == "approved":
        headline, verb = "Approved", "approved"
    elif record.status == "overridden":
        headline, verb = "Approved — break-glass override", "approved via break-glass override"
    elif record.status == "denied":
        headline, verb = "Denied", "denied"
    elif record.status == "timed_out":
        headline, verb = "Expired", None
    elif record.status == "pending":
        headline, verb = "Still pending", None
    else:
        headline, verb = record.status.capitalize(), None
    lines: list[str] = []
    if verb is not None:
        sentence = f"This action was {verb} by {_decider_label(record)}"
        when = _decided_when(record.decided_at)
        if when is not None:
            sentence += f" on {when[0]} at {when[1]}"
        lines.append(sentence + ".")
    elif record.status == "timed_out":
        lines.append(
            "No decision was recorded before the approval window elapsed, "
            "so this action was auto-denied."
        )
    else:
        lines.append("No decision has been recorded yet.")
    lines.append(
        f"Agent `{record.agent_id}` · Tool `{record.tool_name}` · Request `{record.request_id}`"
    )
    if record.decision_reason:
        lines.append(f"Reason: {record.decision_reason}")
    return [
        {"type": "header", "text": {"type": "plain_text", "text": headline}},
        {"type": "section", "text": {"type": "mrkdwn", "text": "\n".join(lines)}},
    ]


def _alert_blocks(payload: dict) -> list[dict]:
    title = payload.get("title", "ACR alert")
    lines = [payload.get("summary", "")]
    for key in ("agent_id", "action_type", "tier", "reason", "correlation_id"):
        if payload.get(key):
            lines.append(f"*{key}*: {payload[key]}")
    return [
        {"type": "header", "text": {"type": "plain_text", "text": title}},
        {"type": "section", "text": {"type": "mrkdwn", "text": "\n".join(x for x in lines if x)}},
    ]


def approval_message_payload(payload: dict) -> dict:
    return {
        "channel": settings.slack_approvals_channel,
        "text": (
            f"Approval required: agent {payload.get('agent_id')} wants to run "
            f"{payload.get('tool_name')} (request {payload.get('request_id')})"
        ),
        "blocks": _approval_blocks(payload),
    }


def alert_message_payload(payload: dict) -> dict:
    return {
        "channel": settings.slack_alerts_channel or settings.slack_approvals_channel,
        "text": payload.get("summary", "ACR alert"),
        "blocks": _alert_blocks(payload),
    }


# ── Delivery (outbox worker side) ────────────────────────────────────────────


async def _slack_post(client: httpx.AsyncClient, method: str, body: dict) -> dict:
    resp = await client.post(
        f"{SLACK_API_BASE}/{method}",
        json=body,
        headers={"Authorization": f"Bearer {settings.slack_bot_token}"},
    )
    if resp.status_code != 200:
        raise DeliveryError(
            f"Slack {method} HTTP {resp.status_code}",
            http_status=resp.status_code,
            retryable=resp.status_code >= 500 or resp.status_code == 429,
        )
    data = resp.json()
    if not data.get("ok"):
        error = str(data.get("error", "unknown_error"))
        raise DeliveryError(
            f"Slack {method} error: {error}",
            http_status=200,
            retryable=error not in _FATAL_SLACK_ERRORS,
        )
    return data


async def deliver(
    db: AsyncSession, row: IntegrationOutboxRecord, client: httpx.AsyncClient
) -> dict | None:
    if row.event_type == "approval_requested":
        data = await _slack_post(client, "chat.postMessage", approval_message_payload(row.payload))
        return {"channel": data.get("channel"), "ts": data.get("ts")}

    if row.event_type == "approval_decided":
        original = await db.execute(
            select(IntegrationOutboxRecord).where(
                IntegrationOutboxRecord.integration == "slack",
                IntegrationOutboxRecord.event_type == "approval_requested",
                IntegrationOutboxRecord.reference == row.reference,
            )
        )
        original_row = original.scalar_one_or_none()
        if original_row is None or not (original_row.delivery_ref or {}).get("ts"):
            if original_row is not None and original_row.status == "dead_letter":
                raise DeliveryError(
                    "Original approval message was never delivered; nothing to update",
                    retryable=False,
                )
            raise DeliveryError("Original approval message not yet delivered; will retry")
        record = await db.execute(
            select(ApprovalRequestRecord).where(ApprovalRequestRecord.request_id == row.reference)
        )
        approval = record.scalar_one_or_none()
        if approval is None:
            raise DeliveryError(f"Approval {row.reference} no longer exists", retryable=False)
        await db.refresh(approval)  # render the committed truth, not a cached copy
        ref = original_row.delivery_ref
        await _slack_post(
            client,
            "chat.update",
            {
                "channel": ref.get("channel") or settings.slack_approvals_channel,
                "ts": ref["ts"],
                "text": f"Approval {approval.status}: {approval.agent_id} / {approval.tool_name}",
                "blocks": _decided_blocks(approval),
            },
        )
        return {"updated_ts": ref["ts"]}

    if row.event_type in ("containment_action", "killswitch_activated"):
        data = await _slack_post(client, "chat.postMessage", alert_message_payload(row.payload))
        return {"channel": data.get("channel"), "ts": data.get("ts")}

    raise DeliveryError(
        f"Slack sender cannot handle event_type '{row.event_type}'", retryable=False
    )
