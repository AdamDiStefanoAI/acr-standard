"""Tests for pillar3_drift baseline and detector — require an in-memory DB."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from acr.db.database import Base
from acr.db.models import DriftMetricRecord
from acr.pillar3_drift.baseline import (
    get_baseline_profile,
    get_or_create_baseline,
    recompute_baseline,
    record_metric_sample,
    reset_baseline,
)
from acr.pillar3_drift.detector import compute_drift_score, run_drift_check
from acr.pillar3_drift.governance import (
    activate_baseline_version,
    approve_baseline_version,
    get_active_baseline_version,
    list_baseline_versions,
    propose_baseline_version,
    reject_baseline_version,
)

# ── Shared DB fixture ─────────────────────────────────────────────────────────


@pytest_asyncio.fixture
async def db():
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        echo=False,
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(bind=engine, expire_on_commit=False, class_=AsyncSession)
    async with factory() as session:
        yield session
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


# ── Helpers ───────────────────────────────────────────────────────────────────


async def _seed_samples(
    db: AsyncSession,
    agent_id: str,
    n: int = 40,
    *,
    with_denials: bool = False,
) -> None:
    """Seed n DriftMetricRecord rows for the given agent."""
    tools = ["tool_a", "tool_b", "tool_c", "tool_d"]
    for i in range(n):
        sample = DriftMetricRecord(
            agent_id=agent_id,
            correlation_id=f"corr-{i}",
            tool_name=tools[i % len(tools)],
            action_type="action",
            policy_denied=(with_denials and i % 5 == 0),
            latency_ms=50 + i,
        )
        db.add(sample)
    await db.commit()


# ── Baseline tests ────────────────────────────────────────────────────────────


class TestDriftBaseline:
    async def test_record_metric_sample_stored(self, db: AsyncSession):
        await record_metric_sample(
            db,
            agent_id="agent-x",
            correlation_id="corr-1",
            tool_name="query_db",
            action_type="read",
            policy_denied=False,
            latency_ms=45,
        )
        await db.commit()

        from sqlalchemy import select

        result = await db.execute(
            select(DriftMetricRecord).where(DriftMetricRecord.agent_id == "agent-x")
        )
        samples = result.scalars().all()
        assert len(samples) == 1
        assert samples[0].tool_name == "query_db"
        assert samples[0].policy_denied is False

    async def test_record_metric_sample_denied(self, db: AsyncSession):
        await record_metric_sample(
            db,
            agent_id="agent-denied",
            correlation_id="corr-d",
            tool_name="delete_customer",
            action_type="delete",
            policy_denied=True,
            latency_ms=None,
        )
        await db.commit()

        from sqlalchemy import select

        result = await db.execute(
            select(DriftMetricRecord).where(DriftMetricRecord.agent_id == "agent-denied")
        )
        sample = result.scalars().first()
        assert sample.policy_denied is True
        assert sample.latency_ms is None

    async def test_get_or_create_baseline_creates_new(self, db: AsyncSession):
        baseline = await get_or_create_baseline(db, "agent-new")
        await db.commit()
        assert baseline.agent_id == "agent-new"
        assert baseline.sample_count == 0
        assert baseline.baseline_data == {}

    async def test_get_or_create_baseline_returns_same_record(self, db: AsyncSession):
        b1 = await get_or_create_baseline(db, "agent-existing")
        await db.commit()
        b2 = await get_or_create_baseline(db, "agent-existing")
        assert b1.id == b2.id

    async def test_recompute_baseline_with_samples(self, db: AsyncSession):
        await _seed_samples(db, "agent-b", n=50)
        baseline = await recompute_baseline(db, "agent-b")
        await db.commit()

        assert baseline.sample_count == 50
        data = baseline.baseline_data
        assert "tool_call_frequency" in data
        assert "denial_rate" in data
        assert "error_rate" in data
        assert "action_diversity" in data
        # std and count stored correctly
        assert data["tool_call_frequency"]["count"] == 50
        assert data["denial_rate"]["std"] > 0

    async def test_recompute_baseline_with_denials(self, db: AsyncSession):
        await _seed_samples(db, "agent-denials", n=40, with_denials=True)
        baseline = await recompute_baseline(db, "agent-denials")
        await db.commit()
        # denial_rate mean should be > 0
        assert baseline.baseline_data["denial_rate"]["mean"] > 0

    async def test_recompute_baseline_no_samples_returns_empty(self, db: AsyncSession):
        baseline = await recompute_baseline(db, "agent-empty")
        await db.commit()
        assert baseline.agent_id == "agent-empty"
        assert baseline.sample_count == 0

    async def test_reset_baseline_clears_data(self, db: AsyncSession):
        await _seed_samples(db, "agent-r", n=40)
        await recompute_baseline(db, "agent-r")
        await db.commit()

        reset = await reset_baseline(db, "agent-r")
        await db.commit()
        assert reset.sample_count == 0
        assert reset.baseline_data == {}

    async def test_get_baseline_profile_returns_metrics(self, db: AsyncSession):
        await _seed_samples(db, "agent-p", n=40)
        await recompute_baseline(db, "agent-p")
        await db.commit()

        profile = await get_baseline_profile(db, "agent-p")
        assert profile.agent_id == "agent-p"
        assert "tool_call_frequency" in profile.metrics
        assert profile.sample_count == 40
        assert profile.is_governed is False

    async def test_get_baseline_profile_no_samples(self, db: AsyncSession):
        profile = await get_baseline_profile(db, "agent-fresh")
        await db.commit()
        assert profile.agent_id == "agent-fresh"
        assert profile.metrics == {}
        assert profile.sample_count == 0

    async def test_propose_list_and_activate_governed_baseline_version(self, db: AsyncSession):
        await _seed_samples(db, "agent-governed", n=40)
        candidate = await propose_baseline_version(
            db,
            agent_id="agent-governed",
            actor="security@example.com",
            notes="Initial candidate",
        )
        await db.commit()

        versions = await list_baseline_versions(db, "agent-governed")
        assert len(versions) == 1
        assert versions[0].baseline_version_id == candidate.baseline_version_id
        assert candidate.status == "candidate"

        approved = await approve_baseline_version(
            db,
            agent_id="agent-governed",
            baseline_version_id=candidate.baseline_version_id,
            actor="security@example.com",
            notes="Reviewed and approved",
        )
        assert approved.status == "approved"

        activated = await activate_baseline_version(
            db,
            agent_id="agent-governed",
            baseline_version_id=candidate.baseline_version_id,
            actor="security@example.com",
            notes="Make this the new normal",
        )
        await db.commit()

        assert activated.status == "active"
        active = await get_active_baseline_version(db, "agent-governed")
        assert active is not None
        assert active.baseline_version_id == candidate.baseline_version_id

        profile = await get_baseline_profile(db, "agent-governed")
        assert profile.is_governed is True
        assert profile.baseline_version_id == candidate.baseline_version_id
        assert profile.baseline_status == "active"

    async def test_reject_baseline_version(self, db: AsyncSession):
        await _seed_samples(db, "agent-reject", n=40)
        candidate = await propose_baseline_version(
            db,
            agent_id="agent-reject",
            actor="security@example.com",
        )
        rejected = await reject_baseline_version(
            db,
            agent_id="agent-reject",
            baseline_version_id=candidate.baseline_version_id,
            actor="security@example.com",
            notes="Unexpected drift source",
        )
        await db.commit()

        assert rejected.status == "rejected"
        assert rejected.rejected_by == "security@example.com"


# ── Detector tests ────────────────────────────────────────────────────────────


class TestDriftDetector:
    async def test_compute_drift_score_baseline_not_ready(self, db: AsyncSession):
        """Agent with no samples → score=0.0, is_baseline_ready=False."""
        score = await compute_drift_score(db, "agent-nobaseline")
        await db.commit()
        assert score.score == 0.0
        assert score.is_baseline_ready is False
        assert score.agent_id == "agent-nobaseline"

    async def test_compute_drift_score_baseline_ready(self, db: AsyncSession):
        """Agent with enough samples + pre-computed baseline → is_baseline_ready=True."""
        await _seed_samples(db, "agent-scored", n=40)
        # compute_drift_score checks baseline_record.sample_count — must pre-compute
        await recompute_baseline(db, "agent-scored")
        await db.commit()

        score = await compute_drift_score(db, "agent-scored")
        await db.commit()

        assert score.is_baseline_ready is True
        assert 0.0 <= score.score <= 1.0
        assert score.agent_id == "agent-scored"
        assert score.sample_count == 40

    async def test_compute_drift_score_ready_without_manual_recompute(self, db: AsyncSession):
        """Regression (red-team finding F-5): samples recorded through the
        live path must make the baseline ready WITHOUT anyone calling
        recompute_baseline by hand. Previously compute_drift_score gated
        on the stored sample_count, which only recompute_baseline sets,
        and recompute was only reachable past that same gate — so every
        fresh agent deadlocked at sample_count=0 and drift readiness
        (and drift-based graduated response) never activated."""
        for i in range(12):
            await record_metric_sample(
                db,
                agent_id="agent-live-path",
                correlation_id=f"corr-live-{i}",
                tool_name="query_db",
                action_type="read",
                policy_denied=False,
                latency_ms=40 + i,
            )
        await db.commit()

        score = await compute_drift_score(db, "agent-live-path")
        await db.commit()

        assert score.is_baseline_ready is True
        assert score.sample_count == 12

    async def test_compute_drift_score_partial_samples_reported(self, db: AsyncSession):
        """Below the minimum, the score stays not-ready but sample_count
        must reflect the samples actually recorded (F-5)."""
        for i in range(5):
            await record_metric_sample(
                db,
                agent_id="agent-partial",
                correlation_id=f"corr-partial-{i}",
                tool_name="query_db",
                action_type="read",
                policy_denied=False,
                latency_ms=40 + i,
            )
        await db.commit()

        score = await compute_drift_score(db, "agent-partial")
        await db.commit()

        assert score.is_baseline_ready is False
        assert score.sample_count == 5
        assert score.score == 0.0

    async def test_compute_drift_score_signals_populated(self, db: AsyncSession):
        """Scored result should include individual signal breakdowns."""
        await _seed_samples(db, "agent-signals", n=40)
        await recompute_baseline(db, "agent-signals")
        await db.commit()

        score = await compute_drift_score(db, "agent-signals")
        await db.commit()

        assert len(score.signals) > 0
        signal_names = {s.name for s in score.signals}
        assert "denial_rate" in signal_names
        assert "tool_call_frequency" in signal_names

    async def test_compute_drift_score_prefers_active_governed_baseline(self, db: AsyncSession):
        await _seed_samples(db, "agent-active", n=40)
        candidate = await propose_baseline_version(
            db,
            agent_id="agent-active",
            actor="security@example.com",
        )
        await approve_baseline_version(
            db,
            agent_id="agent-active",
            baseline_version_id=candidate.baseline_version_id,
            actor="security@example.com",
        )
        await activate_baseline_version(
            db,
            agent_id="agent-active",
            baseline_version_id=candidate.baseline_version_id,
            actor="security@example.com",
        )
        await db.commit()

        score = await compute_drift_score(db, "agent-active")
        await db.commit()

        assert score.is_baseline_ready is True
        assert score.baseline_version_id == candidate.baseline_version_id
        assert score.baseline_status == "active"

    async def test_run_drift_check_no_baseline(self, db: AsyncSession):
        """run_drift_check with no baseline → score not ready, graduated response not called."""
        # apply_graduated_response is imported inside run_drift_check, so patch at source
        with patch(
            "acr.pillar5_containment.graduated.apply_graduated_response",
            new_callable=AsyncMock,
        ) as mock_apply:
            drift = await run_drift_check(db, "agent-nodrift")
        await db.commit()

        assert drift.is_baseline_ready is False
        mock_apply.assert_not_called()

    async def test_run_drift_check_with_baseline_calls_graduated_response(self, db: AsyncSession):
        """run_drift_check with ready baseline invokes graduated response when score > 0."""
        await _seed_samples(db, "agent-check", n=40)
        await recompute_baseline(db, "agent-check")
        await db.commit()

        # Patch at source — apply_graduated_response is lazy-imported inside the function
        with patch(
            "acr.pillar5_containment.graduated.apply_graduated_response",
            new_callable=AsyncMock,
        ) as mock_apply:
            drift = await run_drift_check(db, "agent-check")
        await db.commit()

        assert drift.agent_id == "agent-check"
        if drift.is_baseline_ready and drift.score > 0:
            mock_apply.assert_called_once_with(db, "agent-check", drift.score)


# ── Graduated response tests ──────────────────────────────────────────────────


class TestGraduatedResponse:
    """Direct tests for pillar5_containment/graduated.py."""

    async def test_none_tier_returns_none(self, db: AsyncSession):
        """Score below THROTTLE threshold → no action taken."""
        from acr.pillar5_containment.graduated import apply_graduated_response

        result = await apply_graduated_response(db, "agent-g", 0.3)
        await db.commit()
        assert result is None

    async def test_throttle_tier_records_action(self, db: AsyncSession):
        """Score in THROTTLE range → ContainmentAction with action_type='throttle'."""
        from acr.pillar5_containment.graduated import apply_graduated_response

        result = await apply_graduated_response(db, "agent-throttle", 0.62)
        await db.commit()
        assert result is not None
        assert result.action_type == "throttle"
        assert result.agent_id == "agent-throttle"

    async def test_restrict_tier_records_action(self, db: AsyncSession):
        from acr.pillar5_containment.graduated import apply_graduated_response

        result = await apply_graduated_response(db, "agent-restrict", 0.75)
        await db.commit()
        assert result is not None
        assert result.action_type == "restrict"

    async def test_isolate_tier_records_action(self, db: AsyncSession):
        from acr.pillar5_containment.graduated import apply_graduated_response

        result = await apply_graduated_response(db, "agent-isolate", 0.92)
        await db.commit()
        assert result is not None
        assert result.action_type == "isolate"

    async def test_kill_tier_invokes_kill_switch(self, db: AsyncSession):
        """Score at KILL threshold → kill_agent called."""
        from unittest.mock import AsyncMock, patch

        from acr.pillar5_containment.graduated import apply_graduated_response

        with patch(
            "acr.pillar5_containment.graduated.kill_agent", new_callable=AsyncMock
        ) as mock_kill:
            result = await apply_graduated_response(db, "agent-kill", 0.97)
        await db.commit()
        assert result is not None
        assert result.action_type == "kill"
        mock_kill.assert_awaited_once()
        call_args = mock_kill.call_args
        assert call_args.args[0] == "agent-kill"  # first positional arg is agent_id

    async def test_action_persisted_to_db(self, db: AsyncSession):
        """Containment action should be written to the DB."""
        from sqlalchemy import select

        from acr.db.models import ContainmentActionRecord
        from acr.pillar5_containment.graduated import apply_graduated_response

        await apply_graduated_response(db, "agent-persist", 0.62)
        await db.commit()
        result = await db.execute(
            select(ContainmentActionRecord).where(
                ContainmentActionRecord.agent_id == "agent-persist"
            )
        )
        record = result.scalar_one_or_none()
        assert record is not None
        assert record.action_type == "throttle"
        assert record.drift_score == pytest.approx(0.62)
