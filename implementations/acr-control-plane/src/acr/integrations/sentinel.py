"""Microsoft Sentinel export via the Azure Monitor Logs Ingestion API.

UNVERIFIED — contract-tested against mocks only; no live workspace
verification exists. Docs basis: the Logs Ingestion API is Microsoft's
current documented ingestion path (the HTTP Data Collector API is
deprecated). Shape: OAuth2 client-credentials token from Azure AD with
scope https://monitor.azure.com/.default, then
POST {dce-endpoint}/dataCollectionRules/{dcr-immutable-id}/streams/{stream-name}?api-version=2023-01-01
with a JSON array of records matching the stream's custom table schema.

Records are produced from RECORDED policy decisions only (the outbox
enqueue happens after the §18 recording commit in the gateway), so the
export can lag or fail without ever touching the evidence trail itself.
"""

from __future__ import annotations

import httpx

from acr.config import settings
from acr.db.models import IntegrationOutboxRecord
from acr.integrations.outbox import DeliveryError

API_VERSION = "2023-01-01"
TOKEN_SCOPE = "https://monitor.azure.com/.default"


def decision_record(
    *,
    created_at_iso: str,
    correlation_id: str,
    agent_id: str,
    policy_id: str,
    tool_name: str | None,
    decision: str,
    enforcement_mode: str,
    reason: str | None,
    sequence: int | None,
    latency_ms: int | None,
    bundle_hash: str | None = None,
) -> dict:
    """One stream record for one recorded policy decision."""
    return {
        "TimeGenerated": created_at_iso,
        "CorrelationId": correlation_id,
        "AgentId": agent_id,
        "PolicyId": policy_id,
        "BundleHash": bundle_hash or "",
        "ToolName": tool_name or "",
        "Decision": decision,
        "EnforcementMode": enforcement_mode,
        "Reason": reason or "",
        "Sequence": sequence,
        "LatencyMs": latency_ms,
    }


async def _access_token(client: httpx.AsyncClient) -> str:
    url = f"https://login.microsoftonline.com/{settings.sentinel_tenant_id}/oauth2/v2.0/token"
    resp = await client.post(
        url,
        data={
            "client_id": settings.sentinel_client_id,
            "client_secret": settings.sentinel_client_secret,
            "scope": TOKEN_SCOPE,
            "grant_type": "client_credentials",
        },
    )
    if resp.status_code != 200:
        raise DeliveryError(
            f"Sentinel token request HTTP {resp.status_code}", http_status=resp.status_code
        )
    token = resp.json().get("access_token")
    if not token:
        raise DeliveryError("Sentinel token response carried no access_token")
    return token


async def deliver_batch(rows: list[IntegrationOutboxRecord], client: httpx.AsyncClient) -> None:
    """Send one batch. Raises DeliveryError on any failure; the outbox
    worker applies the outcome (attempt rows, retry, dead-letter) to
    every row in the batch."""
    if not rows:
        return
    token = await _access_token(client)
    endpoint = settings.sentinel_dce_endpoint.rstrip("/")
    url = (
        f"{endpoint}/dataCollectionRules/{settings.sentinel_dcr_immutable_id}"
        f"/streams/{settings.sentinel_stream_name}?api-version={API_VERSION}"
    )
    records = [row.payload.get("record", {}) for row in rows]
    resp = await client.post(url, json=records, headers={"Authorization": f"Bearer {token}"})
    # Logs Ingestion returns 204 No Content on full success.
    if resp.status_code not in (200, 204):
        raise DeliveryError(
            f"Sentinel ingestion HTTP {resp.status_code}",
            http_status=resp.status_code,
            retryable=resp.status_code != 400,
        )
