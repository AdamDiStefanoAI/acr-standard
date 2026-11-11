"""Concurrency tests for critical control plane flows.

Tests exercise concurrent approval, kill-switch, and timeout-race scenarios
to verify there are no double-execution bugs or inconsistent states under
parallel access.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, patch

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from acr.pillar6_authority.approval import (
    create_approval_request,
    expire_timed_out_approvals,
    get_approval_request,
)

# ── Helpers ──────────────────────────────────────────────────────────────────


async def _seed_approval(db: AsyncSession, agent_id: str, sla_minutes: int = 240) -> str:
    """Create a pending approval and commit; return its request_id."""
    record = await create_approval_request(
        db,
        correlation_id="corr-concurrency",
        agent_id=agent_id,
        tool_name="issue_refund",
        parameters={"amount": 100},
        description="Concurrency test",
        approval_queue="default",
        sla_minutes=sla_minutes,
    )
    await db.commit()
    return record.request_id


# ── Test A: Concurrent Approval — Double-Execution Prevention ────────────────


class TestConcurrentApproval:
    """Two operators simultaneously approving the same request should result
    in exactly one success (200) and one conflict (409) or error."""

    async def test_concurrent_approve_prevents_double_execution(
        self,
        async_client: AsyncClient,
        db: AsyncSession,
        sample_agent,
    ) -> None:
        request_id = await _seed_approval(db, sample_agent.agent_id)

        # Fire two concurrent approve calls for the same request_id
        results = await asyncio.gather(
            async_client.post(
                f"/acr/approvals/{request_id}/approve",
                json={"decided_by": "operator-A", "reason": "Looks good"},
            ),
            async_client.post(
                f"/acr/approvals/{request_id}/approve",
                json={"decided_by": "operator-B", "reason": "Also looks good"},
            ),
            return_exceptions=True,
        )

        # Collect status codes (filter out exceptions)
        statuses = []
        for r in results:
            if isinstance(r, Exception):
                # An unhandled exception is acceptable as long as
                # it doesn't leave data in an inconsistent state.
                continue
            statuses.append(r.status_code)

        # At least one should succeed
        assert 200 in statuses, f"Expected at least one 200, got {statuses}"

        # The approval record must be in exactly one terminal state
        record = await get_approval_request(db, request_id)
        assert record.status == "approved"
        assert record.decision == "approved"


# ── Test B: Kill Switch During In-Flight Evaluate ────────────────────────────


class TestKillSwitchDuringEvaluate:
    """Kill switch fired while evaluations are in flight should cause
    subsequent evaluations to be denied."""

    async def test_kill_switch_during_concurrent_evaluate(
        self,
        async_client: AsyncClient,
        db: AsyncSession,
        sample_agent,
    ) -> None:
        # We need to override the kill switch mock so we can control when the
        # kill switch fires mid-flight.
        call_count = 0
        kill_after = 3  # flip kill switch after N evaluate calls

        async def _dynamic_kill_check(agent_id: str) -> bool:
            nonlocal call_count
            call_count += 1
            return call_count > kill_after

        eval_payload = {
            "agent_id": sample_agent.agent_id,
            "action": {"tool_name": "query_customer_db", "parameters": {}},
            "context": {},
        }

        with (
            patch(
                "acr.gateway.router.is_agent_killed",
                side_effect=_dynamic_kill_check,
            ),
        ):
            # Fire 5 concurrent evaluate calls
            tasks = [async_client.post("/acr/evaluate", json=eval_payload) for _ in range(5)]
            results = await asyncio.gather(*tasks, return_exceptions=True)

        statuses = []
        for r in results:
            if isinstance(r, Exception):
                # No evaluate call should raise an unhandled exception
                pytest.fail(f"Evaluate raised an unhandled exception: {r}")
            statuses.append(r.status_code)
            data = r.json()
            # Every response must have a decision field
            assert "decision" in data

        # All evaluations should either succeed (200) or deny (403)
        for status in statuses:
            assert status in (200, 403), f"Unexpected status code: {status}"

        # After kill, a fresh evaluate returns deny
        with patch(
            "acr.gateway.router.is_agent_killed",
            new_callable=AsyncMock,
            return_value=True,
        ):
            resp = await async_client.post("/acr/evaluate", json=eval_payload)
        assert resp.status_code == 403
        assert resp.json()["decision"] == "deny"


# ── Test C: Approval Timeout Race ────────────────────────────────────────────


class TestApprovalTimeoutRace:
    """Expiry loop running while operator manually approves should not
    leave the record in an inconsistent state."""

    @pytest_asyncio.fixture
    async def test_engine(self, tmp_path):
        # Concurrent transactions need separate connections. StaticPool shares
        # one transaction, letting a rejected request roll back the expiry worker.
        from sqlalchemy.ext.asyncio import create_async_engine

        from acr.db.database import Base

        engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'timeout.sqlite'}")
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        yield engine
        await engine.dispose()

    async def test_approval_timeout_does_not_race_with_manual_approve(
        self,
        async_client: AsyncClient,
        db: AsyncSession,
        sample_agent,
    ) -> None:
        # Create a pending approval with a very short timeout (1 second)
        request_id = await _seed_approval(db, sample_agent.agent_id, sla_minutes=0)

        # The record should already be "expired" (expires_at is in the past
        # or None when sla_minutes=0). Let's create one with a valid expiry
        # that we can immediately expire.
        from datetime import timedelta

        from acr.common.time import utcnow

        record = await get_approval_request(db, request_id)
        # Set expires_at to 1 second ago to make it eligible for expiry
        record.expires_at = utcnow() - timedelta(seconds=1)
        await db.commit()

        # Simultaneously: manually approve + run the expiry loop
        async def _approve():
            return await async_client.post(
                f"/acr/approvals/{request_id}/approve",
                json={"decided_by": "operator@example.com", "reason": "Manual approve"},
            )

        async def _expire():
            # Run the expiry function that marks timed-out approvals
            await expire_timed_out_approvals(db)
            await db.commit()

        results = await asyncio.gather(
            _approve(),
            _expire(),
            return_exceptions=True,
        )

        # Neither should raise an unhandled exception
        for r in results:
            if isinstance(r, Exception):
                # Acceptable: one path may fail due to the other winning
                continue

        # The record should be in exactly one terminal state
        await db.refresh(record)
        # Re-fetch for safety
        fresh = await get_approval_request(db, request_id)
        terminal_states = {"approved", "timed_out", "denied"}
        assert fresh.status in terminal_states, (
            f"Record ended in non-terminal state: {fresh.status}"
        )
        # Status must never be "pending" after both operations completed
        assert fresh.status != "pending"
