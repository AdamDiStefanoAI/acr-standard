"""Pillar 6 unit tests: approval queue + HTTP router."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from acr.common.errors import ApprovalNotFoundError
from acr.pillar6_authority.approval import (
    approve,
    create_approval_request,
    deny,
    get_approval_request,
)


class TestApprovalQueue:
    async def test_create_approval(self, db: AsyncSession, sample_agent) -> None:
        record = await create_approval_request(
            db,
            correlation_id="corr-001",
            agent_id=sample_agent.agent_id,
            tool_name="issue_refund",
            parameters={"amount": 250},
            description="High-value refund",
            approval_queue="finance-approvals",
            sla_minutes=240,
        )
        assert record.request_id.startswith("apr-")
        assert record.status == "pending"
        assert record.agent_id == sample_agent.agent_id

    async def test_approve(self, db: AsyncSession, sample_agent) -> None:
        record = await create_approval_request(
            db,
            correlation_id="corr-002",
            agent_id=sample_agent.agent_id,
            tool_name="issue_refund",
            parameters={"amount": 150},
            description=None,
            approval_queue="default",
            sla_minutes=60,
        )
        await db.commit()
        approved = await approve(db, record.request_id, "ops@example.com", "Looks good")
        assert approved.status == "approved"
        assert approved.decided_by == "ops@example.com"

    async def test_deny(self, db: AsyncSession, sample_agent) -> None:
        record = await create_approval_request(
            db,
            correlation_id="corr-003",
            agent_id=sample_agent.agent_id,
            tool_name="issue_refund",
            parameters={"amount": 500},
            description=None,
            approval_queue="default",
            sla_minutes=60,
        )
        await db.commit()
        denied = await deny(db, record.request_id, "ops@example.com", "Too large")
        assert denied.status == "denied"
        assert denied.decision == "denied"

    async def test_not_found(self, db: AsyncSession) -> None:
        with pytest.raises(ApprovalNotFoundError):
            await get_approval_request(db, "apr-nonexistent")


# ── HTTP router tests (cover pillar6_authority/router.py) ─────────────────────


class TestApprovalRouterHTTP:
    """Call the approval endpoints through the real HTTP test client.

    Uses `db` to seed data and `async_client` to hit the API — both are bound
    to the same StaticPool in-memory SQLite engine via conftest fixtures.
    """

    async def _seed_approval(self, db: AsyncSession, sample_agent) -> str:
        """Create a pending approval and commit; return its request_id."""
        record = await create_approval_request(
            db,
            correlation_id="corr-http",
            agent_id=sample_agent.agent_id,
            tool_name="issue_refund",
            parameters={"amount": 300},
            description="HTTP router test",
            approval_queue="finance",
            sla_minutes=240,
        )
        await db.commit()
        return record.request_id

    async def test_list_pending_returns_seeded_approval(
        self, async_client: AsyncClient, db: AsyncSession, sample_agent
    ) -> None:
        await self._seed_approval(db, sample_agent)
        resp = await async_client.get("/acr/approvals")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        assert any(item["tool_name"] == "issue_refund" for item in data)

    async def test_get_approval_by_id(
        self, async_client: AsyncClient, db: AsyncSession, sample_agent
    ) -> None:
        request_id = await self._seed_approval(db, sample_agent)
        resp = await async_client.get(f"/acr/approvals/{request_id}")
        assert resp.status_code == 200
        assert resp.json()["request_id"] == request_id
        assert resp.json()["status"] == "pending"

    async def test_get_approval_not_found(self, async_client: AsyncClient) -> None:
        resp = await async_client.get("/acr/approvals/apr-does-not-exist")
        assert resp.status_code == 404

    async def test_approve_via_http(
        self, async_client: AsyncClient, db: AsyncSession, sample_agent
    ) -> None:
        request_id = await self._seed_approval(db, sample_agent)
        resp = await async_client.post(
            f"/acr/approvals/{request_id}/approve",
            json={"decided_by": "ops@example.com", "reason": "Approved"},
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "approved"
        assert resp.json()["decided_by"] == "test-operator"

    async def test_unbound_approval_cannot_execute_when_enabled(
        self, async_client: AsyncClient, db: AsyncSession, sample_agent
    ) -> None:
        request_id = await self._seed_approval(db, sample_agent)
        with (
            patch.object(
                __import__("acr.pillar6_authority.router", fromlist=["settings"]).settings,
                "execute_allowed_actions",
                True,
            ),
            patch(
                "acr.pillar6_authority.approval.execute_action",
                new_callable=AsyncMock,
                return_value={"status": "executed", "executor": "finance-api"},
            ),
        ):
            resp = await async_client.post(
                f"/acr/approvals/{request_id}/approve",
                json={"decided_by": "ops@example.com", "reason": "Approved"},
            )
        assert resp.status_code == 409
        assert "unbound" in resp.text.lower()

    async def test_deny_via_http(
        self, async_client: AsyncClient, db: AsyncSession, sample_agent
    ) -> None:
        request_id = await self._seed_approval(db, sample_agent)
        resp = await async_client.post(
            f"/acr/approvals/{request_id}/deny",
            json={"decided_by": "ops@example.com", "reason": "Too risky"},
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "denied"

    async def test_override_via_http(
        self, async_client: AsyncClient, db: AsyncSession, sample_agent
    ) -> None:
        request_id = await self._seed_approval(db, sample_agent)
        resp = await async_client.post(
            f"/acr/approvals/{request_id}/override",
            json={"decided_by": "security@example.com", "reason": "Emergency override"},
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "overridden"

    async def test_override_without_reason_returns_422(
        self, async_client: AsyncClient, db: AsyncSession, sample_agent
    ) -> None:
        request_id = await self._seed_approval(db, sample_agent)
        resp = await async_client.post(
            f"/acr/approvals/{request_id}/override",
            json={"decided_by": "ops@example.com", "reason": ""},
        )
        assert resp.status_code == 422
