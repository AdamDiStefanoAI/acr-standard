"""Pillar 4: ACR Telemetry Schema — Pydantic models matching the spec."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

from acr.common.correlation import new_correlation_id
from acr.common.time import iso_utcnow
from acr.config import settings

# ── Sub-objects ───────────────────────────────────────────────────────────────


class AgentTelemetryObject(BaseModel):
    agent_id: str
    agent_name: str | None = None
    purpose: str
    version: str | None = None
    capabilities: list[str] = Field(default_factory=list)
    identity_token_hash: str | None = None


class RequestTelemetryObject(BaseModel):
    request_id: str  # correlation ID
    session_id: str | None = None
    tool_name: str | None = None
    parameters: dict[str, Any] = Field(default_factory=dict)
    description: str | None = None
    context: dict[str, Any] = Field(default_factory=dict)
    intent: dict[str, Any] = Field(default_factory=dict)


class LatencyBreakdown(BaseModel):
    identity_ms: int | None = None
    policy_ms: int | None = None
    drift_ms: int | None = None
    output_filter_ms: int | None = None
    total_ms: int | None = None


class ExecutionObject(BaseModel):
    start_time: str
    end_time: str | None = None
    duration_ms: int | None = None
    latency_breakdown: LatencyBreakdown = Field(default_factory=LatencyBreakdown)


class TriggeredRule(BaseModel):
    rule_id: str
    rule_description: str
    severity: Literal["low", "medium", "high", "critical"] = "medium"


class PolicyResult(BaseModel):
    policy_id: str
    policy_name: str | None = None
    decision: Literal["allow", "deny", "modify", "escalate", "warn"] = "allow"
    reason: str | None = None
    latency_ms: int | None = None
    triggered_rules: list[TriggeredRule] = Field(default_factory=list)


class OutputObject(BaseModel):
    decision: Literal["allow", "deny", "modify", "escalate"]
    reason: str | None = None
    approval_request_id: str | None = None
    filtered: bool = False
    filter_reason: str | None = None
    modified_parameters: dict[str, Any] | None = None
    # Enforcement mode the decision was issued under (v1.5.0 WS1). For
    # `observe` events, `decision` is the would-be decision — what the
    # policy stack decided while the call itself proceeded. Consumers
    # must key on this field to separate observed from enforced verdicts.
    # Defaults to `enforce` so events written before the field existed
    # (and non-gateway event producers) remain valid.
    enforcement_mode: Literal["enforce", "observe"] = "enforce"


class AcrControlPlaneMetadata(BaseModel):
    version: str
    enforcement_point: str = "gateway"


class IntegrityMetadata(BaseModel):
    payload_sha256: str
    previous_event_sha256: str | None = None
    record_signature: str | None = None
    signature_algorithm: Literal["hmac-sha256"] = "hmac-sha256"


class TelemetryMetadata(BaseModel):
    environment: str
    acr_control_plane: AcrControlPlaneMetadata
    drift_score: float | None = None
    anomaly_flags: list[str] = Field(default_factory=list)
    compliance_tags: list[str] = Field(default_factory=list)
    integrity: IntegrityMetadata | None = None


# ── Top-level event ───────────────────────────────────────────────────────────

EventType = Literal[
    "ai_inference",
    "policy_decision",
    "drift_alert",
    "containment_action",
    "human_intervention",
]


class ACRTelemetryEvent(BaseModel):
    """Top-level ACR telemetry event matching the spec schema."""

    acr_version: str = Field(default_factory=lambda: settings.acr_version)
    event_id: str = Field(default_factory=new_correlation_id)
    event_type: EventType
    timestamp: str = Field(default_factory=iso_utcnow)
    agent: AgentTelemetryObject
    request: RequestTelemetryObject
    execution: ExecutionObject
    policies: list[PolicyResult] = Field(default_factory=list)
    output: OutputObject
    metadata: TelemetryMetadata
    custom: dict[str, Any] = Field(default_factory=dict)
