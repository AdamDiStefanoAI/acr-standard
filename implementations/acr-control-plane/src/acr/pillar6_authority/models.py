"""Pillar 6: Human Authority — Pydantic models."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

RiskTier = Literal["low", "medium", "high"]
ApprovalStatus = Literal["pending", "approved", "denied", "overridden", "timed_out"]


class ApprovalRequest(BaseModel):
    request_id: str
    correlation_id: str
    agent_id: str
    tool_name: str
    parameters: dict = Field(default_factory=dict)
    description: str | None = None
    risk_tier: RiskTier = "high"
    approval_queue: str = "default"
    status: ApprovalStatus = "pending"
    sla_minutes: int = 240
    expires_at: datetime | None = None
    created_at: datetime | None = None


class ApprovalDecision(BaseModel):
    reason: str | None = None


class ApprovalResponse(BaseModel):
    request_id: str
    correlation_id: str
    agent_id: str
    tool_name: str
    parameters: dict
    description: str | None
    risk_tier: str
    approval_queue: str
    status: ApprovalStatus
    decision: str | None
    decided_by: str | None
    # WS4: transport identity for chat-channel decisions (both None for
    # decisions made through this API directly).
    decided_channel: str | None = None
    chat_actor_id: str | None = None
    decision_reason: str | None
    sla_minutes: int
    expires_at: datetime | None
    decided_at: datetime | None
    created_at: datetime | None
    execution_result: dict | None = None

    model_config = {"from_attributes": True}
