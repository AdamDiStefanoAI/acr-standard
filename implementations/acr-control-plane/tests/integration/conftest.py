"""Integration test fixtures: real Postgres, Redis, OPA — no mocks."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
import pytest_asyncio
from fastapi import Request as FastAPIRequest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

# Skip the entire integration suite unless explicitly opted in.
if os.environ.get("RUN_INTEGRATION_TESTS", "").lower() != "true":
    pytest.skip("RUN_INTEGRATION_TESTS not set", allow_module_level=True)

TEST_DATABASE_URL = os.environ.get(
    "TEST_DATABASE_URL", "postgresql+asyncpg://acr:acr@localhost:5432/acr_test"
)
TEST_REDIS_URL = os.environ.get("TEST_REDIS_URL", "redis://localhost:6379/1")
TEST_OPA_URL = os.environ.get("TEST_OPA_URL", "http://localhost:8181")

# Patch settings BEFORE importing the app so they take effect everywhere.
os.environ["DATABASE_URL"] = TEST_DATABASE_URL
os.environ["REDIS_URL"] = TEST_REDIS_URL
os.environ["OPA_URL"] = TEST_OPA_URL
os.environ["ACR_ENV"] = "test"
os.environ["JWT_SECRET_KEY"] = "integration_test_secret_not_for_production_at_all"
os.environ["KILLSWITCH_SECRET"] = "integration_killswitch_secret_not_for_production"
os.environ["SCHEMA_BOOTSTRAP_MODE"] = "create"
os.environ["STRICT_DEPENDENCY_STARTUP"] = "false"
os.environ["EXECUTE_ALLOWED_ACTIONS"] = "false"


@pytest.fixture(autouse=True)
def configured_operator_extensions(monkeypatch):
    """Match the services-only export even when parent conftest imported settings first."""
    from acr.config import settings

    extensions = os.environ.get(
        "POLICY_EXTENSION_DIR", str(Path(__file__).resolve().parents[2] / "operator-policies")
    )
    monkeypatch.setattr(settings, "policy_extension_dir", extensions)


# asyncpg pools and the app's cached async clients must stay on the same loop
# as the integration tests. Function-scoped fixtures still clean up per test.
@pytest_asyncio.fixture(scope="session", loop_scope="session")
async def integration_engine():
    """Create a real async Postgres engine for the test suite."""
    engine = create_async_engine(TEST_DATABASE_URL, echo=False)

    # Run Alembic migrations
    from acr.db.database import Base

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    yield engine

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


@pytest_asyncio.fixture(scope="function", loop_scope="session")
async def db(integration_engine) -> AsyncSession:
    """Provide a real Postgres session for each test, rolled back after."""
    factory = async_sessionmaker(
        bind=integration_engine, expire_on_commit=False, class_=AsyncSession
    )
    async with factory() as session:
        yield session
        await session.rollback()


@pytest_asyncio.fixture(scope="function", loop_scope="session")
async def redis_client():
    """Provide a real Redis connection."""
    import redis.asyncio as aioredis

    r = aioredis.from_url(TEST_REDIS_URL, decode_responses=True)
    yield r
    await r.flushdb()
    await r.aclose()


@pytest_asyncio.fixture(scope="function", loop_scope="session")
async def async_client(integration_engine) -> AsyncClient:
    """HTTP test client wired to the real app with real dependencies."""
    from acr.db.database import get_db
    from acr.main import app

    factory = async_sessionmaker(
        bind=integration_engine, expire_on_commit=False, class_=AsyncSession
    )

    async def override_get_db():
        async with factory() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise

    app.dependency_overrides[get_db] = override_get_db

    # Bypass JWT auth for integration tests — use agent_id from request body
    from acr.common.operator_auth import OperatorPrincipal, get_operator_principal
    from acr.gateway.auth import require_agent_token

    async def _mock_auth(request: FastAPIRequest) -> str:
        body = await request.json()
        return body.get("agent_id", "")

    app.dependency_overrides[require_agent_token] = _mock_auth
    app.dependency_overrides[get_operator_principal] = lambda: OperatorPrincipal(
        subject="test-operator",
        roles=frozenset(
            {"agent_admin", "approver", "security_admin", "auditor", "killswitch_operator"}
        ),
    )

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        yield client

    app.dependency_overrides.clear()
