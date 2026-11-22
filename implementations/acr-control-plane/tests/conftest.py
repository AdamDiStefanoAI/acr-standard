"""Test fixtures: in-memory DB, mock OPA, mock kill switch."""

from __future__ import annotations

from collections.abc import AsyncGenerator
from unittest.mock import AsyncMock, patch

import pytest_asyncio
from fastapi import Request as FastAPIRequest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from acr.common.operator_auth import OperatorPrincipal, get_operator_principal
from acr.db.database import Base, get_db
from acr.gateway.auth import require_agent_token
from acr.main import app
from acr.pillar1_identity.models import AgentBoundaries, AgentRegisterRequest
from acr.pillar1_identity.registry import register_agent

# ── Test database (SQLite in-memory) ──────────────────────────────────────────

TEST_DB_URL = "sqlite+aiosqlite:///:memory:"


@pytest_asyncio.fixture(scope="function")
async def test_engine():
    # StaticPool: all connections share the same in-memory SQLite database.
    # Without this, each new connection (i.e. each HTTP request in the test
    # client) opens a fresh empty database and cannot see data written by a
    # previous request.
    engine = create_async_engine(
        TEST_DB_URL,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        echo=False,
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


@pytest_asyncio.fixture(scope="function")
async def db(test_engine) -> AsyncGenerator[AsyncSession, None]:
    factory = async_sessionmaker(bind=test_engine, expire_on_commit=False, class_=AsyncSession)
    async with factory() as session:
        yield session


@pytest_asyncio.fixture(scope="function")
async def async_client(test_engine) -> AsyncGenerator[AsyncClient, None]:
    """HTTP test client with the test DB injected.

    These fixtures run with no Redis, which since the fail-closed posture
    change means an explicitly degraded deployment. Opt in for the duration
    of the fixture, the same way a local developer now must; tests for the
    fail-closed behavior itself live in test_hardening.py and turn the
    opt-in back off.
    """
    from acr.config import settings

    previous_degraded = settings.allow_degraded_dependencies
    settings.allow_degraded_dependencies = True
    factory = async_sessionmaker(bind=test_engine, expire_on_commit=False, class_=AsyncSession)

    async def override_get_db():
        async with factory() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise

    app.dependency_overrides[get_db] = override_get_db

    # Bypass JWT auth in unit tests: read agent_id from the request body so
    # the identity-mismatch check in the router still works correctly.
    async def _mock_auth(request: FastAPIRequest) -> str:
        body = await request.json()
        return body.get("agent_id", "")

    app.dependency_overrides[require_agent_token] = _mock_auth
    app.dependency_overrides[get_operator_principal] = lambda: OperatorPrincipal(
        subject="test-operator",
        roles=frozenset({"agent_admin", "approver", "security_admin", "auditor"}),
    )

    # Mock all external dependencies so tests never need Redis/OPA/real DB.
    # Always patch at the router's import site, not the source modules.
    with (
        patch("acr.gateway.router.is_agent_killed", new_callable=AsyncMock, return_value=False),
        patch(
            "acr.gateway.router.evaluate_policy",
            new_callable=AsyncMock,
            return_value=_make_allow_result(),
        ),
        # Redis not available in tests — all Redis helpers degrade gracefully
        patch("acr.gateway.router.get_redis_or_none", return_value=None),
        # Skip background tasks (they'd hit real DB/Redis)
        patch("acr.gateway.router._queue_background_tasks"),
    ):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            yield client

    settings.allow_degraded_dependencies = previous_degraded
    app.dependency_overrides.clear()


# ── Sample agent fixture ───────────────────────────────────────────────────────


def _make_allow_result():
    from acr.pillar2_policy.models import PolicyDecision, PolicyEvaluationResult

    return PolicyEvaluationResult(
        final_decision="allow",
        decisions=[PolicyDecision(policy_id="acr-allow", decision="allow")],
        latency_ms=5,
    )


@pytest_asyncio.fixture
async def sample_agent(db: AsyncSession):
    req = AgentRegisterRequest(
        agent_id="customer-support-01",
        owner="support-engineering@example.com",
        purpose="Handle customer support tickets",
        risk_tier="medium",
        allowed_tools=["query_customer_db", "send_email", "create_ticket", "issue_refund"],
        forbidden_tools=["delete_customer"],
        boundaries=AgentBoundaries(
            max_actions_per_minute=30,
            max_cost_per_hour_usd=5.0,
            default_action_cost_usd=0.05,
            tool_costs_usd={"query_customer_db": 0.01, "issue_refund": 0.25},
        ),
    )
    record = await register_agent(db, req)
    await db.commit()
    return record
