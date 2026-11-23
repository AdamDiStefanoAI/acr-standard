"""Inbound integration callbacks (Slack / Teams interactivity).

These endpoints are authenticated by the channel's own signature
scheme, verified against the RAW body before any parsing is trusted —
never by operator credentials. An unsigned or badly signed callback is
rejected before it can change anything. A verified callback still
cannot decide anything by itself: the chat user must map to an operator
identity via explicit config, and the decision itself is executed by
the pillar 6 approvals API (see chat_decision.py).
"""

from __future__ import annotations

import json
from urllib.parse import parse_qs

import structlog
from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, Response
from sqlalchemy.ext.asyncio import AsyncSession

from acr.config import settings, slack_approver_map, teams_approver_map
from acr.db.database import get_db
from acr.integrations import slack as slack_integration
from acr.integrations import teams as teams_integration
from acr.integrations.chat_decision import decide_from_chat
from acr.integrations.outbox import enqueue_event

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/acr/integrations", tags=["Integrations"])


@router.post("/slack/actions")
async def slack_actions(request: Request, db: AsyncSession = Depends(get_db)) -> Response:
    if not settings.slack_enabled:
        return JSONResponse(status_code=404, content={"detail": "Slack integration is not enabled"})
    raw = await request.body()
    if not slack_integration.verify_signature(
        settings.slack_signing_secret,
        request.headers.get("x-slack-request-timestamp"),
        raw,
        request.headers.get("x-slack-signature"),
    ):
        logger.warning("slack_callback_signature_rejected")
        return JSONResponse(status_code=401, content={"detail": "Invalid Slack signature"})

    form = parse_qs(raw.decode("utf-8", errors="replace"))
    payload_values = form.get("payload")
    if not payload_values:
        return JSONResponse(status_code=400, content={"detail": "Missing payload"})
    try:
        payload = json.loads(payload_values[0])
    except json.JSONDecodeError:
        return JSONResponse(status_code=400, content={"detail": "Malformed payload"})

    actions = payload.get("actions") or []
    if not actions:
        return Response(status_code=200)
    action = actions[0]
    action_id = action.get("action_id")
    request_id = action.get("value") or ""
    if action_id not in ("acr_approve", "acr_deny") or not request_id:
        return Response(status_code=200)

    chat_user = (payload.get("user") or {}).get("id", "")
    operator_subject = slack_approver_map().get(chat_user)
    if operator_subject is None:
        # Unmapped chat users cannot approve anything. Nothing changes.
        logger.warning("slack_callback_unmapped_user", chat_user=chat_user, request_id=request_id)
        return JSONResponse(
            status_code=200,
            content={
                "text": "You are not mapped to an ACR approver identity, so this action was not applied. No decision was recorded."
            },
        )

    outcome = await decide_from_chat(
        db,
        request_id=request_id,
        action="approve" if action_id == "acr_approve" else "deny",
        channel="slack",
        chat_actor_id=chat_user,
        operator_subject=operator_subject,
    )
    if outcome.error is not None:
        # Already decided / expired / missing: ask the worker to re-render
        # the original message from the record's current state, so what
        # the channel shows is the API's truth, not a local guess. If the
        # real decision event already queued that render, the outbox
        # dedupe makes this a no-op.
        await enqueue_event(
            db,
            integration="slack",
            event_type="approval_decided",
            reference=request_id,
            payload={"request_id": request_id, "refresh": True},
        )
        await db.commit()
    # The worker updates the original message via chat.update from the
    # approval_decided outbox event enqueued by the decision path.
    return Response(status_code=200)


@router.post("/teams/actions")
async def teams_actions(request: Request, db: AsyncSession = Depends(get_db)) -> Response:
    if not settings.teams_enabled:
        return JSONResponse(status_code=404, content={"detail": "Teams integration is not enabled"})
    raw = await request.body()
    try:
        body = json.loads(raw.decode("utf-8", errors="replace"))
    except json.JSONDecodeError:
        return JSONResponse(status_code=400, content={"detail": "Malformed JSON"})

    request_id = str(body.get("request_id", ""))
    action = str(body.get("action", ""))
    authorization = request.headers.get("authorization")
    token_ok = teams_integration.verify_action_token(body.get("acr_token"), request_id, action)
    hmac_ok = teams_integration.verify_outgoing_hmac(raw, authorization)
    if not (token_ok or hmac_ok):
        logger.warning("teams_callback_auth_rejected", request_id=request_id)
        return JSONResponse(
            status_code=401, content={"detail": "Invalid Teams callback authentication"}
        )
    if action not in ("approve", "deny") or not request_id:
        return JSONResponse(status_code=400, content={"detail": "Missing request_id or action"})

    chat_user = str((body.get("from") or {}).get("id") or body.get("actor_id") or "")
    operator_subject = teams_approver_map().get(chat_user)
    if operator_subject is None:
        logger.warning("teams_callback_unmapped_user", chat_user=chat_user, request_id=request_id)
        return JSONResponse(
            status_code=200,
            content=teams_integration.outcome_response_card(
                "You are not mapped to an ACR approver identity, so this action was not applied. No decision was recorded."
            ),
        )

    outcome = await decide_from_chat(
        db,
        request_id=request_id,
        action=action,
        channel="teams",
        chat_actor_id=chat_user,
        operator_subject=operator_subject,
    )
    if outcome.record is not None:
        return JSONResponse(
            status_code=200, content=teams_integration.outcome_card_payload(outcome.record)
        )
    return JSONResponse(
        status_code=200,
        content=teams_integration.outcome_response_card(
            outcome.error or "The approval could not be decided."
        ),
    )
