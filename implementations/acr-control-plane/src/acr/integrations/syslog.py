"""Syslog export: RFC 5424 messages over UDP or TCP.

UNVERIFIED — contract-tested against mocked sockets only; no live
syslog receiver verification exists. Format basis: RFC 5424 message
format (`<PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID
STRUCTURED-DATA MSG`), one message per outbox event, with the event
document carried as JSON in MSG. TCP uses RFC 6587 octet-counted
framing. Transports are plain UDP/TCP only — TLS is not offered in
this release.

Events are the same outbox stream the other emitters consume —
approvals, containment, kill switch, and recorded policy decisions
(enqueued strictly after the §18 recording commit, like the Sentinel
export). Severity is mapped from the event: a kill switch activation
is crit, containment is err, denied outcomes are warning, escalations
are notice, and everything else is info; the facility is configured
(SYSLOG_FACILITY, default 16 = local0).
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import socket
from datetime import UTC

from sqlalchemy.ext.asyncio import AsyncSession

from acr.common.time import utcnow
from acr.config import settings
from acr.db.models import IntegrationOutboxRecord
from acr.integrations.outbox import DeliveryError

_EVENT_TYPES = (
    "approval_requested",
    "approval_decided",
    "containment_action",
    "killswitch_activated",
    "decision_export",
)

# RFC 5424 severity codes (lower is more severe).
_SEVERITY_BY_EVENT = {
    "killswitch_activated": 2,  # crit
    "containment_action": 3,  # err
    "approval_requested": 6,  # info
    "approval_decided": 6,  # info; denials are raised to warning below
    "decision_export": 6,  # info; deny/escalate are adjusted below
}


def event_document(row: IntegrationOutboxRecord) -> dict:
    """The event body carried in the syslog MSG for one row."""
    return {
        "event_type": row.event_type,
        "reference": row.reference,
        "correlation_id": row.correlation_id or "",
        "target": row.target,
        "payload": row.payload,
    }


def _severity(row: IntegrationOutboxRecord) -> int:
    if row.event_type == "approval_decided" and row.payload.get("status") == "denied":
        return 4  # warning
    if row.event_type == "decision_export":
        decision = (row.payload.get("record") or {}).get("Decision")
        if decision == "deny":
            return 4  # warning
        if decision == "escalate":
            return 5  # notice
    return _SEVERITY_BY_EVENT.get(row.event_type, 6)


def format_message(row: IntegrationOutboxRecord) -> bytes:
    """One RFC 5424 message for one outbox row."""
    created = row.created_at or utcnow()
    if created.tzinfo is None:  # SQLite driver drops tz; DB contract is UTC
        created = created.replace(tzinfo=UTC)
    timestamp = created.astimezone(UTC).isoformat().replace("+00:00", "Z")
    pri = settings.syslog_facility * 8 + _severity(row)
    msg = json.dumps(event_document(row), separators=(",", ":"), sort_keys=True)
    header = (
        f"<{pri}>1 {timestamp} {socket.gethostname()} {settings.syslog_app_name} - {row.event_type}"
    )
    return f"{header} - {msg}".encode()


def _frame_tcp(message: bytes) -> bytes:
    """RFC 6587 octet-counted framing for TCP transport."""
    return f"{len(message)} ".encode() + message


async def _send_udp(data: bytes) -> None:
    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(
        asyncio.DatagramProtocol,
        remote_addr=(settings.syslog_host, settings.syslog_port),
    )
    try:
        transport.sendto(data)
    finally:
        transport.close()


async def _send_tcp(data: bytes) -> None:
    _, writer = await asyncio.open_connection(settings.syslog_host, settings.syslog_port)
    try:
        writer.write(_frame_tcp(data))
        await writer.drain()
    finally:
        writer.close()
        with contextlib.suppress(OSError):
            await writer.wait_closed()


async def deliver(db: AsyncSession, row: IntegrationOutboxRecord, client=None) -> dict | None:
    """Send one event as one syslog message. The httpx client the
    outbox worker passes to HTTP senders is unused here."""
    if row.event_type not in _EVENT_TYPES:
        raise DeliveryError(
            f"Syslog sender cannot handle event_type '{row.event_type}'", retryable=False
        )
    if not settings.syslog_host:
        raise DeliveryError("SYSLOG_HOST is not configured", retryable=False)
    protocol = settings.syslog_protocol.lower()
    if protocol not in ("udp", "tcp"):
        raise DeliveryError(
            f"SYSLOG_PROTOCOL must be 'udp' or 'tcp', got '{settings.syslog_protocol}'",
            retryable=False,
        )
    message = format_message(row)
    try:
        if protocol == "tcp":
            await _send_tcp(message)
        else:
            await _send_udp(message)
    except OSError as exc:
        raise DeliveryError(f"Syslog {protocol} delivery failed: {exc}") from exc
    return {"transport": protocol, "bytes": len(message)}
