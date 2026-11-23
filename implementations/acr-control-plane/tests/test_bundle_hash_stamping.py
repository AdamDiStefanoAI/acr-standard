"""Bundle-hash stamping tests (migration 0021).

Decision records now carry the hash of the policy bundle that produced
the evaluation, derived exactly as WS2 policy simulation and the
Policy Studio activation gate derive it: sha256 over the archive bytes
built by build_active_runtime_bundle from the currently active
releases. Stamping happens in the §18 recording path for enforce and
observe decisions alike, and is best-effort evidence: it never changes
an outcome and never becomes a recording failure.

Covered here:
- an enforce-mode decision is stamped with the active bundle's hash
- an observe-mode decision is stamped with the same hash
- the stamp changes when the active bundle changes, tracking the new
  bundle's hash exactly
- with no active releases, the stamp is the core-only bundle's hash
  (the derivation never invents a value or skips stamping)
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from acr.db.models import PolicyDecisionRecord, PolicyReleaseRecord
from acr.pillar1_identity.models import AgentRegisterRequest
from acr.pillar1_identity.registry import register_agent
from acr.pillar2_policy.models import PolicyDecision, PolicyEvaluationResult
from acr.policy_studio.distribution import build_active_runtime_bundle

ALLOW_RESULT = PolicyEvaluationResult(
    final_decision="allow",
    decisions=[PolicyDecision(policy_id="acr-allow", decision="allow")],
    reason=None,
    latency_ms=3,
)
DENY_RESULT = PolicyEvaluationResult(
    final_decision="deny",
    decisions=[PolicyDecision(policy_id="acr-deny-0", decision="deny", reason="blocked")],
    reason="blocked",
    latency_ms=3,
)

REGO_V1 = 'package acr\nescalate if {\n    input.action.tool_name == "issue_refund"\n}'
REGO_V2 = (
    'package acr\ndeny contains "no refunds" if {\n    input.action.tool_name == "issue_refund"\n}'
)


def _body(agent_id: str) -> dict:
    return {
        "agent_id": agent_id,
        "action": {"tool_name": "query_customer_db", "parameters": {"customer_id": "C-001"}},
        "context": {"session_id": "sess-bundle-hash"},
    }


def _patch_policy(result):
    return patch("acr.gateway.router.evaluate_policy", new_callable=AsyncMock, return_value=result)


async def _register(db: AsyncSession, agent_id: str, mode: str = "enforce"):
    record = await register_agent(
        db,
        AgentRegisterRequest(
            agent_id=agent_id,
            owner="bundle-hash-tests@example.com",
            purpose="Bundle hash stamping test agent",
            allowed_tools=["query_customer_db"],
            enforcement_mode=mode,  # type: ignore[arg-type]
        ),
    )
    await db.commit()
    return record


def _release(
    release_id: str, agent_id: str, version: int, rego: str, *, active: bool
) -> PolicyReleaseRecord:
    return PolicyReleaseRecord(
        release_id=release_id,
        draft_id=f"draft-{release_id}",
        agent_id=agent_id,
        version=version,
        name=f"Release {release_id}",
        template="customer_support",
        manifest={"agent_id": agent_id},
        rego_policy=rego,
        status="published",
        activation_status="active" if active else "inactive",
        activated_at=None,
    )


async def _active_bundle_hash(test_engine) -> str:
    """The WS2 derivation over whatever releases are active right now."""
    factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    async with factory() as session:
        result = await session.execute(
            select(PolicyReleaseRecord).where(PolicyReleaseRecord.activation_status == "active")
        )
        records = list(result.scalars().all())
    return build_active_runtime_bundle(records).sha256


async def _records(test_engine, agent_id: str) -> list[PolicyDecisionRecord]:
    factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    async with factory() as session:
        result = await session.execute(
            select(PolicyDecisionRecord)
            .where(PolicyDecisionRecord.agent_id == agent_id)
            .order_by(PolicyDecisionRecord.sequence)
        )
        return list(result.scalars().all())


class TestBundleHashStamping:
    async def test_enforce_decision_carries_active_bundle_hash(
        self, async_client: AsyncClient, db: AsyncSession, test_engine
    ) -> None:
        await _register(db, "bh-enforce")
        db.add(_release("rel-bh-1", "bh-enforce", 1, REGO_V1, active=True))
        await db.commit()
        expected = await _active_bundle_hash(test_engine)

        with _patch_policy(ALLOW_RESULT):
            resp = await async_client.post("/acr/evaluate", json=_body("bh-enforce"))
        assert resp.status_code == 200

        records = await _records(test_engine, "bh-enforce")
        assert len(records) == 1
        assert records[0].enforcement_mode == "enforce"
        assert records[0].bundle_hash == expected
        assert len(records[0].bundle_hash) == 64

    async def test_observe_decision_carries_active_bundle_hash(
        self, async_client: AsyncClient, db: AsyncSession, test_engine
    ) -> None:
        await _register(db, "bh-observe", mode="observe")
        db.add(_release("rel-bh-2", "bh-observe", 1, REGO_V1, active=True))
        await db.commit()
        expected = await _active_bundle_hash(test_engine)

        with _patch_policy(DENY_RESULT):
            resp = await async_client.post("/acr/evaluate", json=_body("bh-observe"))
        assert resp.status_code == 200
        assert resp.json()["would_be_decision"] == "deny"

        records = await _records(test_engine, "bh-observe")
        assert len(records) == 1
        assert records[0].enforcement_mode == "observe"
        assert records[0].decision == "deny"
        assert records[0].bundle_hash == expected

    async def test_stamp_changes_when_active_bundle_changes(
        self, async_client: AsyncClient, db: AsyncSession, test_engine
    ) -> None:
        await _register(db, "bh-change")
        v1 = _release("rel-bh-3a", "bh-change", 1, REGO_V1, active=True)
        db.add(v1)
        await db.commit()
        first_expected = await _active_bundle_hash(test_engine)

        with _patch_policy(ALLOW_RESULT):
            resp = await async_client.post("/acr/evaluate", json=_body("bh-change"))
        assert resp.status_code == 200

        # Supersede v1 with v2: the active bundle's bytes change, so the
        # WS2 hash changes, and the next decision must carry the new one.
        v1.activation_status = "inactive"
        v1.status = "superseded"
        db.add(_release("rel-bh-3b", "bh-change", 2, REGO_V2, active=True))
        await db.commit()
        second_expected = await _active_bundle_hash(test_engine)
        assert second_expected != first_expected

        with _patch_policy(ALLOW_RESULT):
            resp = await async_client.post("/acr/evaluate", json=_body("bh-change"))
        assert resp.status_code == 200

        records = await _records(test_engine, "bh-change")
        assert len(records) == 2
        assert records[0].bundle_hash == first_expected
        assert records[1].bundle_hash == second_expected
        assert records[0].bundle_hash != records[1].bundle_hash

    async def test_no_active_releases_stamps_core_only_bundle_hash(
        self, async_client: AsyncClient, db: AsyncSession, test_engine
    ) -> None:
        await _register(db, "bh-core-only")
        expected = await _active_bundle_hash(test_engine)
        assert expected == build_active_runtime_bundle([]).sha256

        with _patch_policy(ALLOW_RESULT):
            resp = await async_client.post("/acr/evaluate", json=_body("bh-core-only"))
        assert resp.status_code == 200

        records = await _records(test_engine, "bh-core-only")
        assert len(records) == 1
        assert records[0].bundle_hash == expected
