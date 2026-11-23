"""Pillar 4: Observe-mode reporting (v1.5.0 WS1).

Aggregates the policy decisions an agent accumulated while in `observe`
enforcement mode. These are would-be decisions: the policy stack's verdict,
recorded with full §18 semantics, for calls that were allowed to proceed.
The report is the artifact a pilot reads before promoting the agent to
`enforce` — counts by would-be outcome, the tools that would have been
blocked most, and sample decision references for spot-checking.

Read-only. Only rows stamped enforcement_mode='observe' are counted;
enforce-mode decisions for the same agent never leak into this report.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from acr.db.models import PolicyDecisionRecord

# Decisions that would have stopped or gated the call had the agent been
# enforcing. `modify` is excluded: a modification would have proceeded.
_BLOCKING_DECISIONS = ("deny", "escalate")


class ObserveToolCount(BaseModel):
    tool_name: str
    deny_count: int = 0
    escalate_count: int = 0
    blocking_total: int = 0


class ObserveDecisionSample(BaseModel):
    correlation_id: str
    sequence: int | None
    decision: str
    tool_name: str | None
    reason: str | None
    created_at: datetime


class ObserveReport(BaseModel):
    agent_id: str
    enforcement_mode: str  # the agent's CURRENT mode, for context
    window_start: datetime
    window_end: datetime
    total_decisions: int
    counts_by_decision: dict[str, int] = Field(default_factory=dict)
    top_blocked_tools: list[ObserveToolCount] = Field(default_factory=list)
    samples: list[ObserveDecisionSample] = Field(default_factory=list)


async def build_observe_report(
    db: AsyncSession,
    *,
    agent_id: str,
    current_mode: str,
    window_start: datetime,
    window_end: datetime,
    top_limit: int = 10,
    sample_limit: int = 20,
) -> ObserveReport:
    """Aggregate one agent's observe-mode decisions inside [start, end]."""
    base = (
        PolicyDecisionRecord.agent_id == agent_id,
        PolicyDecisionRecord.enforcement_mode == "observe",
        PolicyDecisionRecord.created_at >= window_start,
        PolicyDecisionRecord.created_at <= window_end,
    )

    counts_result = await db.execute(
        select(PolicyDecisionRecord.decision, func.count())
        .where(*base)
        .group_by(PolicyDecisionRecord.decision)
    )
    counts = {str(decision): int(count) for decision, count in counts_result.all()}

    tools_result = await db.execute(
        select(
            PolicyDecisionRecord.tool_name,
            PolicyDecisionRecord.decision,
            func.count(),
        )
        .where(*base, PolicyDecisionRecord.decision.in_(_BLOCKING_DECISIONS))
        .group_by(PolicyDecisionRecord.tool_name, PolicyDecisionRecord.decision)
    )
    tools: dict[str, ObserveToolCount] = {}
    for tool_name, decision, count in tools_result.all():
        entry = tools.setdefault(
            tool_name or "(unknown)", ObserveToolCount(tool_name=tool_name or "(unknown)")
        )
        if decision == "deny":
            entry.deny_count += int(count)
        elif decision == "escalate":
            entry.escalate_count += int(count)
        entry.blocking_total += int(count)
    top_tools = sorted(tools.values(), key=lambda t: (-t.blocking_total, t.tool_name))[:top_limit]

    samples_result = await db.execute(
        select(PolicyDecisionRecord)
        .where(*base)
        .order_by(PolicyDecisionRecord.created_at.desc(), PolicyDecisionRecord.sequence.desc())
        .limit(sample_limit)
    )
    samples = [
        ObserveDecisionSample(
            correlation_id=r.correlation_id,
            sequence=r.sequence,
            decision=r.decision,
            tool_name=r.tool_name,
            reason=r.reason,
            created_at=r.created_at,
        )
        for r in samples_result.scalars().all()
    ]

    return ObserveReport(
        agent_id=agent_id,
        enforcement_mode=current_mode,
        window_start=window_start,
        window_end=window_end,
        total_decisions=sum(counts.values()),
        counts_by_decision=counts,
        top_blocked_tools=top_tools,
        samples=samples,
    )
