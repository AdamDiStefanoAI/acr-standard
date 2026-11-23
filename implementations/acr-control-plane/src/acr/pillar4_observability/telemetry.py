"""Pillar 4: Structured JSON telemetry event generation and persistence."""

from __future__ import annotations

import structlog
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from acr.config import settings
from acr.db.models import TelemetryEventRecord
from acr.pillar4_observability.integrity import (
    extract_payload_hash,
    payload_sha256,
    remove_integrity_metadata,
    sign_payload_hash,
)
from acr.pillar4_observability.schema import (
    AcrControlPlaneMetadata,
    ACRTelemetryEvent,
    AgentTelemetryObject,
    EventType,
    ExecutionObject,
    LatencyBreakdown,
    OutputObject,
    PolicyResult,
    RequestTelemetryObject,
    TelemetryMetadata,
)

logger = structlog.get_logger(__name__)


def build_event(
    *,
    event_type: EventType,
    agent_id: str,
    agent_purpose: str,
    agent_capabilities: list[str],
    correlation_id: str,
    session_id: str | None,
    tool_name: str | None,
    parameters: dict,
    description: str | None,
    context: dict,
    intent: dict,
    start_time: str,
    end_time: str,
    duration_ms: int,
    latency_breakdown: LatencyBreakdown,
    policies: list[PolicyResult],
    output_decision: str,
    output_reason: str | None,
    approval_request_id: str | None,
    drift_score: float | None,
    enforcement_mode: str = "enforce",
    output_filtered: bool = False,
    filter_reason: str | None = None,
    modified_parameters: dict | None = None,
    custom: dict | None = None,
) -> ACRTelemetryEvent:
    return ACRTelemetryEvent(
        event_type=event_type,
        agent=AgentTelemetryObject(
            agent_id=agent_id,
            purpose=agent_purpose,
            capabilities=agent_capabilities,
        ),
        request=RequestTelemetryObject(
            request_id=correlation_id,
            session_id=session_id,
            tool_name=tool_name,
            parameters=parameters,
            description=description,
            context=context,
            intent=intent,
        ),
        execution=ExecutionObject(
            start_time=start_time,
            end_time=end_time,
            duration_ms=duration_ms,
            latency_breakdown=latency_breakdown,
        ),
        policies=policies,
        output=OutputObject(
            decision=output_decision,  # type: ignore[arg-type]
            reason=output_reason,
            approval_request_id=approval_request_id,
            filtered=output_filtered,
            filter_reason=filter_reason,
            modified_parameters=modified_parameters,
            enforcement_mode=enforcement_mode,  # type: ignore[arg-type]
        ),
        metadata=TelemetryMetadata(
            environment=settings.acr_env,
            acr_control_plane=AcrControlPlaneMetadata(version=settings.acr_version),
            drift_score=drift_score,
        ),
        custom=custom or {},
    )


async def persist_event(db: AsyncSession, event: ACRTelemetryEvent) -> None:
    """Write the telemetry event to PostgreSQL (async, non-blocking in background task)."""
    payload = event.model_dump(mode="json")
    previous_hash = await _latest_correlation_event_hash(db, event.request.request_id)
    payload_hash = payload_sha256(remove_integrity_metadata(payload))
    payload.setdefault("metadata", {})["integrity"] = {
        "payload_sha256": payload_hash,
        "previous_event_sha256": previous_hash,
        "record_signature": sign_payload_hash(payload_hash, previous_hash),
        "signature_algorithm": "hmac-sha256",
    }

    record = TelemetryEventRecord(
        event_id=event.event_id,
        correlation_id=event.request.request_id,
        event_type=event.event_type,
        agent_id=event.agent.agent_id,
        payload=payload,
    )
    db.add(record)
    await db.flush()


def log_event(event: ACRTelemetryEvent) -> None:
    """Emit the event as a structured JSON log line."""
    logger.info(
        "acr_event",
        acr_version=event.acr_version,
        event_id=event.event_id,
        event_type=event.event_type,
        correlation_id=event.request.request_id,
        agent_id=event.agent.agent_id,
        tool_name=event.request.tool_name,
        decision=event.output.decision,
        duration_ms=event.execution.duration_ms,
        drift_score=event.metadata.drift_score,
    )


async def _latest_correlation_event_hash(db: AsyncSession, correlation_id: str) -> str | None:
    result = await db.execute(
        select(TelemetryEventRecord.payload)
        .where(TelemetryEventRecord.correlation_id == correlation_id)
        .order_by(desc(TelemetryEventRecord.created_at))
        .limit(1)
    )
    payload = result.scalar_one_or_none()
    if not isinstance(payload, dict):
        return None
    return extract_payload_hash(payload)
