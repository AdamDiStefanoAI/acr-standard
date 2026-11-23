"""WS4 delivery-hardening regression tests: the integration outbox on a
schema built by the Alembic migrations.

Every other DB test in this repo builds its schema from ORM metadata
(``Base.metadata.create_all``). That hid a real defect: migration 0020
created ``integration_outbox.next_attempt_at`` / ``created_at`` /
``updated_at`` and ``integration_delivery_attempts.attempted_at`` as
NOT NULL with no database default, while the models declare
``server_default=func.now()``. On a migrated schema — every real
deployment — outbox inserts failed with NOT NULL violations and, the
enqueue being failure-isolated by design, no integration ever
delivered. Migration 0023 restores the defaults.

These tests therefore build their schema by running
``alembic upgrade head`` against a scratch database, never create_all.
They live in the integration suite (real Postgres) alongside the other
real-dependency tests, and the concurrency test additionally needs two
genuinely separate connection pools for the race to be meaningful.
"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlparse, urlunparse

import asyncpg
import httpx
import pytest
import pytest_asyncio
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from acr.config import settings
from acr.db.models import (
    IntegrationDeliveryAttemptRecord,
    IntegrationOutboxRecord,
)
from acr.integrations.outbox import enqueue_event, process_outbox_once
from acr.pillar1_identity.models import AgentBoundaries, AgentRegisterRequest
from acr.pillar1_identity.registry import register_agent
from acr.pillar6_authority.approval import create_approval_request

pytestmark = pytest.mark.asyncio(loop_scope="session")

IMPL_ROOT = Path(__file__).resolve().parents[2]
BASE_URL = os.environ.get(
    "TEST_DATABASE_URL", "postgresql+asyncpg://acr:acr@localhost:5432/acr_test"
)
MIGRATED_DB = "acr_outbox_migrated_test"


def _url_with_db(url: str, db: str) -> str:
    parsed = urlparse(url)
    return urlunparse(parsed._replace(path=f"/{db}"))


MIGRATED_URL = _url_with_db(BASE_URL, MIGRATED_DB)


async def _admin(sql: str) -> None:
    from urllib.parse import parse_qs

    parsed = urlparse(BASE_URL)
    query = parse_qs(parsed.query)
    conn = await asyncpg.connect(
        host=parsed.hostname or query.get("host", [None])[0],
        port=parsed.port or 5432,
        user=parsed.username,
        password=parsed.password,
        database="postgres",
    )
    try:
        await conn.execute(sql)
    finally:
        await conn.close()


@pytest_asyncio.fixture(scope="module", loop_scope="session")
async def migrated_engine():
    """Create a scratch database and migrate it to head with Alembic."""
    await _admin(f'DROP DATABASE IF EXISTS "{MIGRATED_DB}" WITH (FORCE)')
    await _admin(f'CREATE DATABASE "{MIGRATED_DB}"')
    env = dict(os.environ)
    env["DATABASE_URL"] = MIGRATED_URL
    result = subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        cwd=IMPL_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=600,
    )
    assert result.returncode == 0, f"alembic upgrade head failed:\n{result.stdout}\n{result.stderr}"
    engine = create_async_engine(MIGRATED_URL, echo=False)
    yield engine
    await engine.dispose()
    await _admin(f'DROP DATABASE IF EXISTS "{MIGRATED_DB}" WITH (FORCE)')


@pytest_asyncio.fixture(loop_scope="session")
async def mdb(migrated_engine) -> AsyncSession:
    factory = async_sessionmaker(bind=migrated_engine, expire_on_commit=False, class_=AsyncSession)
    async with factory() as session:
        yield session
        await session.rollback()


def _enable_slack() -> dict:
    saved = {
        k: getattr(settings, k)
        for k in (
            "slack_enabled",
            "slack_bot_token",
            "slack_signing_secret",
            "slack_approvals_channel",
        )
    }
    settings.slack_enabled = True
    settings.slack_bot_token = "xoxb-test-token"
    settings.slack_signing_secret = "test-signing-secret"
    settings.slack_approvals_channel = "C-APPROVE"
    return saved


def _restore(saved: dict) -> None:
    for key, value in saved.items():
        setattr(settings, key, value)


def _slack_client(calls: list, delay: float = 0.0) -> httpx.AsyncClient:
    async def handler(request: httpx.Request) -> httpx.Response:
        if delay:
            await asyncio.sleep(delay)
        body = json.loads(request.content)
        calls.append((request.url.path, body))
        if request.url.path.endswith("chat.postMessage"):
            return httpx.Response(
                200, json={"ok": True, "ts": "1700.001", "channel": body["channel"]}
            )
        return httpx.Response(404, json={"ok": False, "error": "unknown_method"})

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


class TestMigratedSchemaOutbox:
    async def test_outbox_insert_uses_server_defaults(self, mdb: AsyncSession) -> None:
        """enqueue_event must persist a row on the migrated schema.

        Pre-0023 this returned None: the insert died on
        next_attempt_at's missing default and the savepoint guard
        swallowed it — the exact production failure.
        """
        row = await enqueue_event(
            mdb,
            integration="slack",
            event_type="approval_requested",
            reference="apr-migrated-1",
            payload={"probe": True},
            target="C-APPROVE",
            correlation_id="corr-migrated-1",
        )
        assert row is not None
        await mdb.commit()
        await mdb.refresh(row)
        assert row.next_attempt_at is not None
        assert row.created_at is not None
        assert row.updated_at is not None

    async def test_delivery_attempt_insert_uses_server_default(self, mdb: AsyncSession) -> None:
        """integration_delivery_attempts.attempted_at drifted the same way."""
        row = await enqueue_event(
            mdb,
            integration="slack",
            event_type="approval_requested",
            reference="apr-migrated-2",
            payload={"probe": True},
            target="C-APPROVE",
        )
        assert row is not None
        await mdb.flush()
        attempt = IntegrationDeliveryAttemptRecord(
            outbox_id=row.id, attempt_number=1, result="success", http_status=200
        )
        mdb.add(attempt)
        await mdb.commit()
        await mdb.refresh(attempt)
        assert attempt.attempted_at is not None

    async def test_approval_notify_delivers_on_migrated_schema(self, mdb: AsyncSession) -> None:
        """Approval → notify → outbox row → delivered, end to end."""
        saved = _enable_slack()
        try:
            agent = await register_agent(
                mdb,
                AgentRegisterRequest(
                    agent_id="migrated-support-01",
                    owner="support@example.com",
                    purpose="Migrated-schema regression",
                    risk_tier="medium",
                    allowed_tools=["issue_refund"],
                    forbidden_tools=[],
                    boundaries=AgentBoundaries(
                        max_actions_per_minute=30,
                        max_cost_per_hour_usd=5.0,
                        default_action_cost_usd=0.05,
                        tool_costs_usd={"issue_refund": 0.25},
                    ),
                ),
            )
            await mdb.commit()
            record = await create_approval_request(
                mdb,
                correlation_id="corr-migrated-approval",
                agent_id=agent.agent_id,
                tool_name="issue_refund",
                parameters={"amount_usd": 25},
                description="Refund a customer",
                approval_queue="default",
                sla_minutes=240,
            )
            await mdb.commit()

            rows = list(
                (
                    await mdb.execute(
                        select(IntegrationOutboxRecord).where(
                            IntegrationOutboxRecord.integration == "slack",
                            IntegrationOutboxRecord.event_type == "approval_requested",
                            IntegrationOutboxRecord.reference == record.request_id,
                        )
                    )
                )
                .scalars()
                .all()
            )
            assert len(rows) == 1

            calls: list = []
            async with _slack_client(calls) as client:
                await process_outbox_once(mdb, client)
            # The drain also delivers rows left pending by sibling
            # tests (shared scratch DB) — scope assertions to this
            # approval's own message.
            posts = [
                c
                for c in calls
                if c[0].endswith("chat.postMessage") and record.request_id in json.dumps(c[1])
            ]
            assert len(posts) == 1
            await mdb.refresh(rows[0])
            assert rows[0].status == "delivered"
        finally:
            _restore(saved)


class TestConcurrentDrainersOnMigratedSchema:
    async def test_two_drainers_deliver_exactly_once(
        self, migrated_engine, mdb: AsyncSession
    ) -> None:
        """One pending row, two concurrent drains, one provider call.

        Regression for the duplicate-delivery race: the drain used to
        SELECT pending rows and claim them afterwards, so two gateway
        workers could both select the same row and both deliver it.
        The claim is now a single conditional UPDATE (SKIP LOCKED on
        Postgres), so exactly one drainer owns the row.
        """
        row = await enqueue_event(
            mdb,
            integration="slack",
            event_type="approval_requested",
            reference="apr-migrated-race",
            payload={
                "request_id": "apr-migrated-race",
                "correlation_id": "corr-migrated-race",
                "agent_id": "race-agent",
                "tool_name": "issue_refund",
                "approval_queue": "default",
                "risk_tier": "high",
            },
            target="C-APPROVE",
        )
        assert row is not None
        await mdb.commit()

        calls: list = []

        async def drain() -> dict:
            engine = create_async_engine(MIGRATED_URL, echo=False)
            factory = async_sessionmaker(bind=engine, expire_on_commit=False, class_=AsyncSession)
            try:
                async with (
                    factory() as session,
                    _slack_client(calls, delay=0.25) as client,
                ):
                    return await process_outbox_once(session, client)
            finally:
                await engine.dispose()

        results = await asyncio.gather(drain(), drain())
        # Scope to this race's own message: sibling tests share the
        # scratch DB and their rows may drain here too.
        posts = [
            c
            for c in calls
            if c[0].endswith("chat.postMessage") and "apr-migrated-race" in json.dumps(c[1])
        ]
        assert len(posts) == 1
        assert sum(r["delivered"] for r in results) >= 1

        await mdb.refresh(row)
        assert row.status == "delivered"
        assert row.attempts == 1
        attempts = list(
            (
                await mdb.execute(
                    select(IntegrationDeliveryAttemptRecord).where(
                        IntegrationDeliveryAttemptRecord.outbox_id == row.id
                    )
                )
            )
            .scalars()
            .all()
        )
        assert len(attempts) == 1 and attempts[0].result == "success"
