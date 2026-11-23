"""Microsoft Teams integration: approval cards, outcome posts, alerts.

UNVERIFIED — built to Microsoft's published formats (incoming webhook
Adaptive Card envelope, Action.Http actions, outgoing-webhook HMAC
authentication) and contract-tested against mocked endpoints only. No
live tenant verification exists; docs/integrations.md says so plainly.

Mechanics: approval requests are posted to the configured incoming
webhook as an Adaptive Card whose Approve/Deny Action.Http buttons post
back to this control plane's callback with a per-action signed token
(HMAC over request id + action + expiry, keyed by the callback secret).
The callback also accepts the Teams outgoing-webhook scheme
(Authorization: HMAC <base64>) when a deployment routes actions that
way. Incoming webhooks cannot edit a posted message, so a decision is
announced as a follow-up outcome card on the same webhook — the pillar 6
record remains the only source of truth either way.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from acr.config import settings
from acr.db.models import ApprovalRequestRecord, IntegrationOutboxRecord
from acr.integrations.outbox import DeliveryError

ACTION_TOKEN_TTL_SECONDS = 24 * 3600


# ── Action tokens + outgoing-webhook HMAC (inbound auth) ────────────────────


def sign_action_token(request_id: str, action: str, *, now: int | None = None) -> str:
    exp = (int(time.time()) if now is None else now) + ACTION_TOKEN_TTL_SECONDS
    msg = f"{request_id}.{action}.{exp}".encode()
    sig = hmac.new(settings.teams_callback_secret.encode(), msg, hashlib.sha256).hexdigest()
    return f"{exp}.{sig}"


def verify_action_token(
    token: str | None, request_id: str, action: str, *, now: int | None = None
) -> bool:
    if not token or not settings.teams_callback_secret:
        return False
    try:
        exp_text, sig = token.split(".", 1)
        exp = int(exp_text)
    except (ValueError, AttributeError):
        return False
    if exp < (int(time.time()) if now is None else now):
        return False
    msg = f"{request_id}.{action}.{exp}".encode()
    expected = hmac.new(settings.teams_callback_secret.encode(), msg, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, sig)


def verify_outgoing_hmac(raw_body: bytes, authorization: str | None) -> bool:
    """Teams outgoing-webhook scheme: Authorization: HMAC <base64 digest>,
    keyed by the base64-decoded security key from the webhook setup."""
    if not authorization or not settings.teams_callback_secret:
        return False
    scheme, _, value = authorization.partition(" ")
    if scheme != "HMAC" or not value:
        return False
    try:
        key = base64.b64decode(settings.teams_callback_secret, validate=True)
    except Exception:
        return False
    expected = base64.b64encode(hmac.new(key, raw_body, hashlib.sha256).digest()).decode()
    return hmac.compare_digest(expected, value.strip())


# ── Card construction ────────────────────────────────────────────────────────


def _card(body: list[dict], actions: list[dict] | None = None) -> dict:
    card: dict = {
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "type": "AdaptiveCard",
        "version": "1.4",
        "body": body,
    }
    if actions:
        card["actions"] = actions
    return card


def _envelope(card: dict) -> dict:
    return {
        "type": "message",
        "attachments": [
            {
                "contentType": "application/vnd.microsoft.card.adaptive",
                "contentUrl": None,
                "content": card,
            }
        ],
    }


def _text(text: str, *, weight: str | None = None, size: str | None = None) -> dict:
    block: dict = {"type": "TextBlock", "text": text, "wrap": True}
    if weight:
        block["weight"] = weight
    if size:
        block["size"] = size
    return block


def _facts(pairs: list[tuple[str, str]]) -> dict:
    return {
        "type": "FactSet",
        "facts": [{"title": k, "value": v} for k, v in pairs if v],
    }


def approval_card_payload(payload: dict) -> dict:
    request_id = payload.get("request_id", "")
    base = settings.teams_callback_base_url.rstrip("/")
    callback_url = f"{base}/acr/integrations/teams/actions"

    def action_http(title: str, action: str) -> dict:
        body = json.dumps(
            {
                "request_id": request_id,
                "action": action,
                "acr_token": sign_action_token(request_id, action),
            }
        )
        return {
            "type": "Action.Http",
            "title": title,
            "method": "POST",
            "url": callback_url,
            "headers": [{"name": "Content-Type", "value": "application/json"}],
            "body": body,
        }

    card = _card(
        [
            _text("Approval required", weight="Bolder", size="Medium"),
            _facts(
                [
                    ("Agent", str(payload.get("agent_id", "?"))),
                    ("Tool", str(payload.get("tool_name", "?"))),
                    ("Queue", str(payload.get("approval_queue", "default"))),
                    ("Risk tier", str(payload.get("risk_tier", "high"))),
                    ("Expires", str(payload.get("expires_at", ""))),
                    ("Request", request_id),
                    ("Correlation", str(payload.get("correlation_id", ""))),
                ]
            ),
        ]
        + ([_text(str(payload["description"]))] if payload.get("description") else []),
        actions=[action_http("Approve", "approve"), action_http("Deny", "deny")],
    )
    return _envelope(card)


def outcome_card_payload(record: ApprovalRequestRecord) -> dict:
    headline = {
        "approved": "Approved",
        "overridden": "Approved via break-glass override",
        "timed_out": "Expired — approval SLA elapsed, auto-denied",
        "denied": "Denied",
    }.get(record.status, record.status)
    facts = [
        ("Agent", record.agent_id),
        ("Tool", record.tool_name),
        ("Request", record.request_id),
    ]
    if record.decided_by:
        facts.append(("Decided by", record.decided_by))
    if record.decided_at:
        facts.append(("Decided at", record.decided_at.isoformat()))
    card = _card(
        [_text(f"Approval {headline.lower()}", weight="Bolder", size="Medium"), _facts(facts)]
    )
    return _envelope(card)


def alert_card_payload(payload: dict) -> dict:
    card = _card(
        [
            _text(str(payload.get("title", "ACR alert")), weight="Bolder", size="Medium"),
            _text(str(payload.get("summary", ""))),
            _facts(
                [
                    ("Agent", str(payload.get("agent_id", ""))),
                    ("Action", str(payload.get("action_type", ""))),
                    ("Tier", str(payload.get("tier", ""))),
                    ("Reason", str(payload.get("reason", ""))),
                    ("Correlation", str(payload.get("correlation_id", ""))),
                ]
            ),
        ]
    )
    return _envelope(card)


def outcome_response_card(text: str) -> dict:
    """Card returned as the HTTP response to a Teams action callback."""
    return _envelope(_card([_text(text, weight="Bolder")]))


# ── Delivery (outbox worker side) ────────────────────────────────────────────


async def _post_webhook(client: httpx.AsyncClient, body: dict) -> None:
    resp = await client.post(settings.teams_webhook_url, json=body)
    if resp.status_code >= 300:
        raise DeliveryError(
            f"Teams webhook HTTP {resp.status_code}",
            http_status=resp.status_code,
            retryable=resp.status_code >= 500 or resp.status_code == 429,
        )


async def deliver(
    db: AsyncSession, row: IntegrationOutboxRecord, client: httpx.AsyncClient
) -> dict | None:
    if row.event_type == "approval_requested":
        await _post_webhook(client, approval_card_payload(row.payload))
        return {"via": "incoming_webhook"}
    if row.event_type == "approval_decided":
        result = await db.execute(
            select(ApprovalRequestRecord).where(ApprovalRequestRecord.request_id == row.reference)
        )
        approval = result.scalar_one_or_none()
        if approval is None:
            raise DeliveryError(f"Approval {row.reference} no longer exists", retryable=False)
        await db.refresh(approval)  # render the committed truth, not a cached copy
        await _post_webhook(client, outcome_card_payload(approval))
        return {"via": "incoming_webhook"}
    if row.event_type in ("containment_action", "killswitch_activated"):
        await _post_webhook(client, alert_card_payload(row.payload))
        return {"via": "incoming_webhook"}
    raise DeliveryError(
        f"Teams sender cannot handle event_type '{row.event_type}'", retryable=False
    )
