"""Splunk export via the HTTP Event Collector (HEC).

UNVERIFIED — contract-tested against mocks only; no live Splunk
instance verification exists. Docs basis: HEC accepts newline-delimited
JSON event envelopes in a single POST to /services/collector/event,
authorized with `Authorization: Splunk <token>`, and answers HTTP 200
with a JSON body whose `code` is 0 on success (nonzero codes are
errors even though the HTTP status is 200).

Events are the same outbox stream the other emitters consume —
approvals, containment, kill switch, and recorded policy decisions
(enqueued strictly after the §18 recording commit, like the Sentinel
export) — wrapped in the HEC envelope with the configured index,
source, and sourcetype. The HEC token comes only from the deployment
environment; it is never logged and never enters a payload.
"""

from __future__ import annotations

import json
from datetime import UTC

import httpx

from acr.common.time import utcnow
from acr.config import settings
from acr.db.models import IntegrationOutboxRecord
from acr.integrations.outbox import DeliveryError

# HEC error codes that retrying cannot fix — the token itself is
# disabled, inactive, or invalid; an operator has to repair the
# configuration. Mirrors the fatal-error classification in slack.py
# (_FATAL_SLACK_ERRORS): these dead-letter on the first attempt.
_FATAL_HEC_CODES = {1, 3, 5, 8}


def event_document(row: IntegrationOutboxRecord) -> dict:
    """The event body carried inside the HEC envelope for one row."""
    return {
        "event_type": row.event_type,
        "reference": row.reference,
        "correlation_id": row.correlation_id or "",
        "target": row.target,
        "payload": row.payload,
    }


def hec_envelope(row: IntegrationOutboxRecord) -> dict:
    """One HEC event envelope for one outbox row."""
    created = row.created_at or utcnow()
    if created.tzinfo is None:  # SQLite driver drops tz; DB contract is UTC
        created = created.replace(tzinfo=UTC)
    envelope: dict = {
        "time": created.timestamp(),
        "source": settings.splunk_hec_source,
        "sourcetype": settings.splunk_hec_sourcetype,
        "event": event_document(row),
    }
    if settings.splunk_hec_index:
        envelope["index"] = settings.splunk_hec_index
    return envelope


def _collector_url() -> str:
    url = settings.splunk_hec_url.rstrip("/")
    if url.endswith("/services/collector"):
        url += "/event"
    return url


async def deliver_batch(rows: list[IntegrationOutboxRecord], client: httpx.AsyncClient) -> None:
    """Send one batch: many envelopes, newline-delimited, in one POST.

    Raises DeliveryError on any failure; the outbox worker applies the
    outcome (attempt rows, retry, dead-letter) to every row in the
    batch — batching changes the HTTP shape, never the evidence shape.
    """
    if not rows:
        return
    if not settings.splunk_hec_url or not settings.splunk_hec_token:
        raise DeliveryError("Splunk HEC URL/token not configured", retryable=False)
    body = "\n".join(json.dumps(hec_envelope(row)) for row in rows)
    resp = await client.post(
        _collector_url(),
        content=body,
        headers={
            "Authorization": f"Splunk {settings.splunk_hec_token}",
            "Content-Type": "application/json",
        },
    )
    if resp.status_code != 200:
        raise DeliveryError(
            f"Splunk HEC HTTP {resp.status_code}",
            http_status=resp.status_code,
            retryable=resp.status_code >= 500 or resp.status_code == 429,
        )
    try:
        data = resp.json()
    except ValueError:
        data = {}
    code = data.get("code")
    if code != 0:
        raise DeliveryError(
            f"Splunk HEC error code {code}: {data.get('text', '')}",
            http_status=200,
            retryable=code not in _FATAL_HEC_CODES,
        )
