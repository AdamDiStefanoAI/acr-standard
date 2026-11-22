"""Pillar 5: Self-Healing & Containment — models."""

from __future__ import annotations

from enum import IntEnum

from pydantic import BaseModel


class ContainmentTier(IntEnum):
    """Graduated response tiers, per spec."""

    NONE = 0
    THROTTLE = 1  # drift >= 0.60 — reduce rate limit 50%
    RESTRICT = 2  # drift >= 0.75 — remove high-risk tools
    ISOLATE = 3  # drift >= 0.90 — read-only mode
    KILL = 4  # drift >= 0.95 — full shutdown


DRIFT_THRESHOLDS: dict[ContainmentTier, float] = {
    ContainmentTier.THROTTLE: 0.60,
    ContainmentTier.RESTRICT: 0.75,
    ContainmentTier.ISOLATE: 0.90,
    ContainmentTier.KILL: 0.95,
}


class KillSwitchState(BaseModel):
    agent_id: str
    is_killed: bool
    reason: str | None = None
    killed_at: str | None = None
    killed_by: str | None = None


class KillRequest(BaseModel):
    agent_id: str
    reason: str
    operator_id: str | None = None


class RestoreRequest(BaseModel):
    agent_id: str
    reason: str | None = None
    operator_id: str | None = None


class ContainmentAction(BaseModel):
    agent_id: str
    tier: ContainmentTier
    action_type: str
    reason: str
    drift_score: float | None = None
    correlation_id: str | None = None
