"""Pillar 3: Drift scoring engine — computes composite drift score from baseline."""

from __future__ import annotations

from datetime import timedelta

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from acr.common.time import utcnow
from acr.db.models import DriftMetricRecord
from acr.pillar3_drift.baseline import recompute_baseline
from acr.pillar3_drift.governance import get_active_baseline_version
from acr.pillar3_drift.models import DriftScore
from acr.pillar3_drift.signals import (
    MIN_BASELINE_SAMPLES,
    RawMetrics,
    composite_drift_score,
    compute_signals,
)

logger = structlog.get_logger(__name__)


async def _collect_recent_metrics(
    db: AsyncSession,
    agent_id: str,
    window_minutes: int = 60,
) -> RawMetrics:
    """Collect raw metrics for the agent over the recent window."""
    cutoff = utcnow() - timedelta(minutes=window_minutes)

    result = await db.execute(
        select(DriftMetricRecord).where(
            DriftMetricRecord.agent_id == agent_id,
            DriftMetricRecord.created_at >= cutoff,
        )
    )
    samples = result.scalars().all()
    n = len(samples)

    if n == 0:
        return RawMetrics(
            tool_calls_per_minute=0.0,
            denial_rate=0.0,
            error_rate=0.0,
            action_diversity=0.0,
        )

    freq = n / window_minutes

    denials = sum(1 for s in samples if s.policy_denied)
    denial_rate = denials / n

    errors = sum(1 for s in samples if s.latency_ms is None)
    error_rate = errors / n

    import math

    tool_counts: dict[str, int] = {}
    for s in samples:
        t = s.tool_name or "_unknown"
        tool_counts[t] = tool_counts.get(t, 0) + 1
    entropy = 0.0
    for count in tool_counts.values():
        p = count / n
        entropy -= p * math.log2(p)
    max_e = math.log2(len(tool_counts)) if len(tool_counts) > 1 else 1.0
    action_diversity = entropy / max_e if max_e > 0 else 0.0

    return RawMetrics(
        tool_calls_per_minute=freq,
        denial_rate=denial_rate,
        error_rate=error_rate,
        action_diversity=action_diversity,
    )


async def compute_drift_score(db: AsyncSession, agent_id: str) -> DriftScore:
    """
    Compute the current drift score for an agent.
    This is called by the async background worker — NOT in the hot gateway path.
    """
    active_baseline = await get_active_baseline_version(db, agent_id)
    baseline_version_id: str | None = None
    baseline_status: str | None = None

    if active_baseline is not None:
        sample_count = active_baseline.sample_count
        baseline_data = active_baseline.baseline_data or {}
        baseline_version_id = active_baseline.baseline_version_id
        baseline_status = active_baseline.status
        if sample_count < MIN_BASELINE_SAMPLES:
            return DriftScore(
                agent_id=agent_id,
                score=0.0,
                signals=[],
                sample_count=sample_count,
                is_baseline_ready=False,
                baseline_version_id=baseline_version_id,
                baseline_status=baseline_status,
            )
    else:
        # Recompute FIRST: the stored sample_count is only ever set by
        # recompute_baseline, so gating on it before recomputing deadlocks
        # every fresh agent at sample_count=0 — samples land in
        # drift_metrics but the baseline record never reflects them and
        # is_baseline_ready can never become true. (The governance propose
        # path recomputes, but nothing in the evaluate/background flow
        # ever reaches it for a new agent.) This is the same recompute
        # the ready path already performs on every call below; with no
        # samples recorded it returns the empty baseline record and the
        # not-ready result is unchanged.
        baseline_record = await recompute_baseline(db, agent_id)

        if baseline_record.sample_count < MIN_BASELINE_SAMPLES:
            # Not enough baseline data yet
            return DriftScore(
                agent_id=agent_id,
                score=0.0,
                signals=[],
                sample_count=baseline_record.sample_count,
                is_baseline_ready=False,
                baseline_version_id=None,
                baseline_status=None,
            )

        baseline_data = baseline_record.baseline_data
        sample_count = baseline_record.sample_count

    current_metrics = await _collect_recent_metrics(db, agent_id, window_minutes=60)
    signals = compute_signals(current_metrics, baseline_data)
    score = composite_drift_score(signals)

    logger.info(
        "drift_score_computed",
        agent_id=agent_id,
        score=score,
        signals={s.name: round(s.z_score, 3) for s in signals},
    )

    return DriftScore(
        agent_id=agent_id,
        score=round(score, 4),
        signals=signals,
        sample_count=sample_count,
        is_baseline_ready=True,
        baseline_version_id=baseline_version_id,
        baseline_status=baseline_status,
    )


async def run_drift_check(db: AsyncSession, agent_id: str) -> DriftScore:
    """
    Full drift check: compute score + apply graduated response if needed.
    Called by the background worker after each gateway evaluation.
    """
    from acr.pillar5_containment.graduated import apply_graduated_response

    drift = await compute_drift_score(db, agent_id)

    if drift.is_baseline_ready and drift.score > 0:
        await apply_graduated_response(db, agent_id, drift.score)

    return drift
