"""ServiceNow integration: incident creation via the Table API.

UNVERIFIED — built to ServiceNow's published Table API
(POST /api/now/table/incident) and contract-tested against mocks only.
No live instance verification exists; docs/integrations.md says so.

Incidents are created for containment events always (when enabled) and
for approval denials only when SERVICENOW_INCIDENT_ON_DENY is set. The
ACR correlation id goes into the incident's native correlation_id field
and the work notes, so an incident can always be traced back to the
decision record that produced it.
"""

from __future__ import annotations

import httpx
from sqlalchemy.ext.asyncio import AsyncSession

from acr.config import settings
from acr.db.models import IntegrationOutboxRecord
from acr.integrations.outbox import DeliveryError


def incident_body(payload: dict) -> dict:
    correlation_id = str(payload.get("correlation_id", ""))
    lines = [
        f"Source: ACR Control Plane ({payload.get('event_type', 'event')})",
        f"Correlation ID: {correlation_id}",
    ]
    for key in ("agent_id", "action_type", "tier", "tool_name", "request_id", "decided_by"):
        if payload.get(key):
            lines.append(f"{key}: {payload[key]}")
    if payload.get("reason"):
        lines.append(f"Reason: {payload['reason']}")
    return {
        "short_description": str(payload.get("title", "ACR event"))[:160],
        "description": "\n".join(lines),
        "work_notes": "\n".join(lines),
        "correlation_id": correlation_id,
        "category": "software",
        "urgency": "2",
        "impact": "2",
    }


async def deliver(
    db: AsyncSession, row: IntegrationOutboxRecord, client: httpx.AsyncClient
) -> dict | None:
    if row.event_type not in ("containment_action", "killswitch_activated", "approval_decided"):
        raise DeliveryError(
            f"ServiceNow sender cannot handle event_type '{row.event_type}'", retryable=False
        )
    instance = settings.servicenow_instance_url.rstrip("/")
    resp = await client.post(
        f"{instance}/api/now/table/incident",
        json=incident_body(row.payload),
        auth=(settings.servicenow_username, settings.servicenow_password),
        headers={"Accept": "application/json", "Content-Type": "application/json"},
    )
    if resp.status_code not in (200, 201):
        raise DeliveryError(
            f"ServiceNow incident create HTTP {resp.status_code}",
            http_status=resp.status_code,
            retryable=resp.status_code >= 500 or resp.status_code == 429,
        )
    result = resp.json().get("result", {})
    return {"sys_id": result.get("sys_id"), "number": result.get("number")}
