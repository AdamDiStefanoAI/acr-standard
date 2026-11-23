"""Shared gateway request/response models for server and SDK consumers."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

from acr.pillar2_policy.models import PolicyDecision

DecisionLiteral = Literal["allow", "deny", "modify", "escalate"]


class ActionRequest(BaseModel):
    tool_name: str
    parameters: dict[str, Any] = Field(default_factory=dict)
    description: str | None = None


class IntentRequest(BaseModel):
    goal: str | None = None
    justification: str | None = None
    expected_effects: list[str] = Field(default_factory=list)
    requested_by_step: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class EvaluateRequest(BaseModel):
    agent_id: str
    action: ActionRequest
    context: dict[str, Any] = Field(default_factory=dict)
    intent: IntentRequest | None = None


class EvaluateResponse(BaseModel):
    decision: DecisionLiteral
    correlation_id: str | None = None
    reason: str | None = None
    error_code: str | None = None
    # Enforcement mode the evaluation ran under (v1.5.0 WS1). In `observe`
    # mode `decision` is the effective outcome (the call proceeds, so
    # "allow") and `would_be_decision` carries what the policy stack
    # decided; `enforced` is False. In `enforce` mode `would_be_decision`
    # is None and `enforced` is True.
    enforcement_mode: Literal["enforce", "observe"] | None = None
    would_be_decision: DecisionLiteral | None = None
    enforced: bool | None = None
    approval_request_id: str | None = None
    approval_queue: str | None = None
    sla_minutes: int | None = None
    policy_decisions: list[PolicyDecision] = Field(default_factory=list)
    drift_score: float | None = None
    latency_ms: int | None = None
    estimated_cost_usd: float | None = None
    authoritative_hourly_spend_usd: float | None = None
    modified_action: ActionRequest | None = None
    execution_result: dict[str, Any] | None = None

    model_config = {"extra": "allow"}

    @property
    def is_allowed(self) -> bool:
        return self.decision in {"allow", "modify"}

    @property
    def requires_approval(self) -> bool:
        return self.decision == "escalate"

    @property
    def was_modified(self) -> bool:
        return self.decision == "modify"
