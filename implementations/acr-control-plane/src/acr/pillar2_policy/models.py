"""Pillar 2: Policy enforcement — Pydantic models."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class PolicyDecision(BaseModel):
    policy_id: str
    decision: Literal["allow", "deny", "modify", "escalate"] = "allow"
    reason: str | None = None
    latency_ms: int | None = None


class OPAInput(BaseModel):
    """Input document sent to OPA for evaluation."""

    agent: dict
    action: dict
    context: dict


class OPAResponse(BaseModel):
    result: dict = Field(default_factory=dict)


class PolicyEvaluationResult(BaseModel):
    """Aggregated result from OPA evaluation."""

    policy_identity: dict | None = None
    final_decision: Literal["allow", "deny", "modify", "escalate"]
    decisions: list[PolicyDecision]
    reason: str | None = None
    approval_queue: str | None = None
    sla_minutes: int | None = None
    modified_action: dict | None = None
    modified_parameters: dict | None = None
    latency_ms: int = 0
