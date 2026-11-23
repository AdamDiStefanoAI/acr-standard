"""Observe mode tests (v1.5.0 WS1).

Observe mode lets an agent run against real traffic with full §18 evidence
semantics while the call itself proceeds. The security claim is narrow and
total: mode lives only on the stored agent record, changes only through
the operator-only transition endpoint, and never exempts the agent from
containment or the kill switch.

Covered here:
- registration / manifest / response carry the mode; the generic update
  endpoint cannot change it; the dedicated transition endpoint can, and
  rejects retired agents
- observe evaluations are recorded synchronously (sequence + mode stamp)
  and proceed on would-be deny and would-be approval; no approval request
  is created for an observed escalation
- recording failure in observe mode still fails secure (503)
- enforce agents on the same stack are completely unaffected
- the mode-confusion battery: headers, body fields, context, parameters,
  tool names, and the generic update endpoint all fail to flip mode
- containment exemption: kill switch and graduated isolate/restrict apply
  to observe-mode agents exactly as to enforcing ones
- approvals queued under enforce keep pillar 6 semantics across a flip
- the observe report aggregates only observe-mode decisions
"""

from __future__ import annotations

from datetime import timedelta
from unittest.mock import AsyncMock, patch

from fakeredis.aioredis import FakeRedis
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from acr.common.operator_auth import OperatorPrincipal, get_operator_principal
from acr.common.time import utcnow
from acr.db.models import ApprovalRequestRecord, PolicyDecisionRecord
from acr.main import app
from acr.pillar1_identity.models import AgentRegisterRequest
from acr.pillar1_identity.registry import register_agent, transition_lifecycle
from acr.pillar2_policy.models import PolicyDecision, PolicyEvaluationResult

DENY_RESULT = PolicyEvaluationResult(
    final_decision="deny",
    decisions=[PolicyDecision(policy_id="acr-deny-0", decision="deny", reason="blocked")],
    reason="blocked",
    latency_ms=3,
)
ESCALATE_RESULT = PolicyEvaluationResult(
    final_decision="escalate",
    decisions=[
        PolicyDecision(policy_id="acr-escalate", decision="escalate", reason="Needs approval")
    ],
    reason="Needs approval",
    latency_ms=4,
)


def _body(agent_id: str, **extra) -> dict:
    body = {
        "agent_id": agent_id,
        "action": {"tool_name": "query_customer_db", "parameters": {"customer_id": "C-001"}},
        "context": {"session_id": "sess-observe"},
    }
    body.update(extra)
    return body


async def _register(db: AsyncSession, agent_id: str, mode: str = "enforce"):
    record = await register_agent(
        db,
        AgentRegisterRequest(
            agent_id=agent_id,
            owner="observe-tests@example.com",
            purpose="Observe mode test agent",
            allowed_tools=["query_customer_db", "send_email", "issue_refund"],
            enforcement_mode=mode,  # type: ignore[arg-type]
        ),
    )
    await db.commit()
    return record


async def _records(test_engine, agent_id: str) -> list[PolicyDecisionRecord]:
    factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    async with factory() as session:
        result = await session.execute(
            select(PolicyDecisionRecord)
            .where(PolicyDecisionRecord.agent_id == agent_id)
            .order_by(PolicyDecisionRecord.sequence)
        )
        return list(result.scalars().all())


async def _approvals(test_engine, agent_id: str) -> list[ApprovalRequestRecord]:
    factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    async with factory() as session:
        result = await session.execute(
            select(ApprovalRequestRecord).where(ApprovalRequestRecord.agent_id == agent_id)
        )
        return list(result.scalars().all())


def _patch_policy(result):
    return patch("acr.gateway.router.evaluate_policy", new_callable=AsyncMock, return_value=result)


# ── Registration, visibility, and the write paths ─────────────────────────────


class TestModeRegistrationAndTransitions:
    async def test_default_mode_is_enforce(self, db: AsyncSession) -> None:
        record = await _register(db, "obs-default")
        assert record.enforcement_mode == "enforce"

    async def test_register_directly_in_observe_via_api(self, async_client: AsyncClient) -> None:
        resp = await async_client.post(
            "/acr/agents",
            json={
                "agent_id": "obs-api",
                "owner": "observe-tests@example.com",
                "purpose": "Observe mode test agent",
                "enforcement_mode": "observe",
            },
        )
        assert resp.status_code == 201
        assert resp.json()["enforcement_mode"] == "observe"

    async def test_generic_update_cannot_change_mode(
        self, async_client: AsyncClient, db: AsyncSession
    ) -> None:
        await _register(db, "obs-update")
        resp = await async_client.put(
            "/acr/agents/obs-update",
            json={"purpose": "Updated purpose", "enforcement_mode": "observe"},
        )
        assert resp.status_code == 200
        assert resp.json()["enforcement_mode"] == "enforce"
        got = await async_client.get("/acr/agents/obs-update")
        assert got.json()["enforcement_mode"] == "enforce"

    async def test_transition_endpoint_changes_mode_both_ways(
        self, async_client: AsyncClient, db: AsyncSession
    ) -> None:
        await _register(db, "obs-flip")
        resp = await async_client.post(
            "/acr/agents/obs-flip/enforcement-mode",
            json={"target_mode": "observe", "reason": "pilot start"},
        )
        assert resp.status_code == 200
        assert resp.json()["enforcement_mode"] == "observe"
        resp = await async_client.post(
            "/acr/agents/obs-flip/enforcement-mode",
            json={"target_mode": "enforce", "reason": "pilot complete"},
        )
        assert resp.status_code == 200
        assert resp.json()["enforcement_mode"] == "enforce"

    async def test_transition_rejects_invalid_mode(
        self, async_client: AsyncClient, db: AsyncSession
    ) -> None:
        await _register(db, "obs-invalid")
        resp = await async_client.post(
            "/acr/agents/obs-invalid/enforcement-mode",
            json={"target_mode": "shadow"},
        )
        assert resp.status_code == 422

    async def test_transition_rejects_retired_agent(
        self, async_client: AsyncClient, db: AsyncSession
    ) -> None:
        await _register(db, "obs-retired")
        await transition_lifecycle(db, "obs-retired", "retired")
        await db.commit()
        resp = await async_client.post(
            "/acr/agents/obs-retired/enforcement-mode",
            json={"target_mode": "observe"},
        )
        assert resp.status_code == 403
        assert resp.json()["error_code"] == "AGENT_LIFECYCLE_INVALID"

    async def test_auditor_cannot_transition_but_can_read_report(
        self, async_client: AsyncClient, db: AsyncSession
    ) -> None:
        await _register(db, "obs-authz", mode="observe")
        app.dependency_overrides[get_operator_principal] = lambda: OperatorPrincipal(
            subject="auditor-only", roles=frozenset({"auditor"})
        )
        try:
            resp = await async_client.post(
                "/acr/agents/obs-authz/enforcement-mode",
                json={"target_mode": "enforce"},
            )
            assert resp.status_code == 403
            resp = await async_client.get("/acr/agents/obs-authz/observe-report")
            assert resp.status_code == 200
        finally:
            app.dependency_overrides[get_operator_principal] = lambda: OperatorPrincipal(
                subject="test-operator",
                roles=frozenset({"agent_admin", "approver", "security_admin", "auditor"}),
            )


# ── Evaluate behavior ─────────────────────────────────────────────────────────


class TestObserveEvaluation:
    async def test_observe_deny_is_recorded_and_proceeds(
        self, async_client: AsyncClient, db: AsyncSession, test_engine
    ) -> None:
        await _register(db, "obs-deny", mode="observe")
        with _patch_policy(DENY_RESULT):
            resp = await async_client.post("/acr/evaluate", json=_body("obs-deny"))
        assert resp.status_code == 200
        data = resp.json()
        assert data["decision"] == "allow"
        assert data["enforcement_mode"] == "observe"
        assert data["would_be_decision"] == "deny"
        assert data["enforced"] is False

        records = await _records(test_engine, "obs-deny")
        assert len(records) == 1
        assert records[0].decision == "deny"
        assert records[0].enforcement_mode == "observe"
        assert records[0].sequence == 1

    async def test_observe_escalate_proceeds_without_creating_approval(
        self, async_client: AsyncClient, db: AsyncSession, test_engine
    ) -> None:
        await _register(db, "obs-esc", mode="observe")
        with _patch_policy(ESCALATE_RESULT):
            resp = await async_client.post("/acr/evaluate", json=_body("obs-esc"))
        assert resp.status_code == 200
        data = resp.json()
        assert data["would_be_decision"] == "escalate"
        assert "approval_request_id" not in data
        assert await _approvals(test_engine, "obs-esc") == []
        records = await _records(test_engine, "obs-esc")
        assert len(records) == 1
        assert records[0].decision == "escalate"
        assert records[0].enforcement_mode == "observe"

    async def test_observe_allow_and_sequence_progression(
        self, async_client: AsyncClient, db: AsyncSession, test_engine
    ) -> None:
        await _register(db, "obs-allow", mode="observe")
        resp1 = await async_client.post("/acr/evaluate", json=_body("obs-allow"))
        with _patch_policy(DENY_RESULT):
            resp2 = await async_client.post("/acr/evaluate", json=_body("obs-allow"))
        assert resp1.json()["would_be_decision"] == "allow"
        assert resp2.json()["would_be_decision"] == "deny"
        records = await _records(test_engine, "obs-allow")
        assert [r.sequence for r in records] == [1, 2]
        assert all(r.enforcement_mode == "observe" for r in records)

    async def test_observe_recording_failure_still_fails_secure(
        self, async_client: AsyncClient, db: AsyncSession
    ) -> None:
        await _register(db, "obs-503", mode="observe")
        with patch(
            "acr.gateway.router._record_policy_decisions",
            new_callable=AsyncMock,
            side_effect=RuntimeError("db down"),
        ):
            resp = await async_client.post("/acr/evaluate", json=_body("obs-503"))
        assert resp.status_code == 503
        assert resp.json()["error_code"] == "EVIDENCE_PERSISTENCE_FAILED"

    async def test_enforce_agents_unaffected_on_same_stack(
        self, async_client: AsyncClient, db: AsyncSession, test_engine
    ) -> None:
        await _register(db, "obs-enforce-peer", mode="enforce")
        with _patch_policy(DENY_RESULT):
            resp = await async_client.post("/acr/evaluate", json=_body("obs-enforce-peer"))
        assert resp.status_code == 403
        data = resp.json()
        assert data["decision"] == "deny"
        assert data["enforcement_mode"] == "enforce"
        assert data["enforced"] is True
        records = await _records(test_engine, "obs-enforce-peer")
        assert records[0].enforcement_mode == "enforce"

        with _patch_policy(ESCALATE_RESULT):
            resp = await async_client.post("/acr/evaluate", json=_body("obs-enforce-peer"))
        assert resp.status_code == 202
        assert resp.json()["approval_request_id"]
        assert len(await _approvals(test_engine, "obs-enforce-peer")) == 1


# ── Mode-confusion battery ────────────────────────────────────────────────────


class TestModeConfusion:
    """Nothing in a request may move an enforce agent into observe."""

    async def test_mode_header_is_ignored(
        self, async_client: AsyncClient, db: AsyncSession
    ) -> None:
        await _register(db, "conf-header")
        with _patch_policy(DENY_RESULT):
            resp = await async_client.post(
                "/acr/evaluate",
                json=_body("conf-header"),
                headers={"X-Enforcement-Mode": "observe", "X-ACR-Mode": "observe"},
            )
        assert resp.status_code == 403
        assert resp.json()["decision"] == "deny"

    async def test_mode_body_field_is_ignored(
        self, async_client: AsyncClient, db: AsyncSession
    ) -> None:
        await _register(db, "conf-body")
        with _patch_policy(DENY_RESULT):
            resp = await async_client.post(
                "/acr/evaluate",
                json=_body("conf-body", enforcement_mode="observe", mode="observe"),
            )
        assert resp.status_code == 403

    async def test_mode_context_field_is_ignored(
        self, async_client: AsyncClient, db: AsyncSession
    ) -> None:
        await _register(db, "conf-context")
        body = _body("conf-context")
        body["context"] = {"session_id": "s", "enforcement_mode": "observe"}
        with _patch_policy(DENY_RESULT):
            resp = await async_client.post("/acr/evaluate", json=body)
        assert resp.status_code == 403

    async def test_mode_parameter_and_tool_name_tricks_are_ignored(
        self, async_client: AsyncClient, db: AsyncSession
    ) -> None:
        await _register(db, "conf-params")
        body = _body("conf-params")
        body["action"]["parameters"] = {
            "customer_id": "C-001",
            "enforcement_mode": "observe",
            "mode": "observe",
        }
        with _patch_policy(DENY_RESULT):
            resp = await async_client.post("/acr/evaluate", json=body)
        assert resp.status_code == 403
        # A tool name smuggling the word changes nothing either.
        body["action"]["tool_name"] = "observe_query_customer_db"
        with _patch_policy(DENY_RESULT):
            resp = await async_client.post("/acr/evaluate", json=body)
        assert resp.status_code == 403
        got = await async_client.get("/acr/agents/conf-params")
        assert got.json()["enforcement_mode"] == "enforce"


# ── Containment exemption ─────────────────────────────────────────────────────


class TestObserveContainment:
    async def test_kill_switch_still_denies_observe_agent(
        self, async_client: AsyncClient, db: AsyncSession, test_engine
    ) -> None:
        await _register(db, "obs-killed", mode="observe")
        with patch("acr.gateway.router.is_agent_killed", new_callable=AsyncMock, return_value=True):
            resp = await async_client.post("/acr/evaluate", json=_body("obs-killed"))
        assert resp.status_code == 403
        assert resp.json()["decision"] == "deny"
        # Containment fires before evaluation and recording, as in enforce.
        assert await _records(test_engine, "obs-killed") == []

    async def test_isolate_still_escalates_observe_agent(
        self, async_client: AsyncClient, db: AsyncSession
    ) -> None:
        await _register(db, "obs-isolated", mode="observe")
        redis = FakeRedis(decode_responses=True)
        await redis.set("acr:isolate:obs-isolated", "1")
        with patch("acr.gateway.router.get_redis_or_none", return_value=redis):
            resp = await async_client.post("/acr/evaluate", json=_body("obs-isolated"))
        assert resp.status_code == 202
        data = resp.json()
        assert data["decision"] == "escalate"
        assert data["reason"] == "agent_isolated_all_actions_require_approval"

    async def test_restrict_still_denies_observe_agent(
        self, async_client: AsyncClient, db: AsyncSession
    ) -> None:
        await _register(db, "obs-restricted", mode="observe")
        redis = FakeRedis(decode_responses=True)
        await redis.set("acr:restrict:obs-restricted", '["send_email"]')
        with patch("acr.gateway.router.get_redis_or_none", return_value=redis):
            resp = await async_client.post("/acr/evaluate", json=_body("obs-restricted"))
        assert resp.status_code == 403
        data = resp.json()
        assert data["decision"] == "deny"
        assert data["reason"] == "agent_restricted_tool_not_allowed"


# ── Queued approvals across a mode flip ───────────────────────────────────────


class TestQueuedApprovalsAcrossFlip:
    async def test_approval_issued_under_enforce_keeps_pillar6_semantics(
        self, async_client: AsyncClient, db: AsyncSession, test_engine
    ) -> None:
        await _register(db, "flip-queue", mode="enforce")
        with _patch_policy(ESCALATE_RESULT):
            resp = await async_client.post("/acr/evaluate", json=_body("flip-queue"))
        assert resp.status_code == 202
        request_id = resp.json()["approval_request_id"]

        # Flip to observe: the queued approval must not be auto-approved,
        # auto-denied, or made executable without its recorded decision.
        flip = await async_client.post(
            "/acr/agents/flip-queue/enforcement-mode",
            json={"target_mode": "observe", "reason": "pilot"},
        )
        assert flip.status_code == 200

        got = await async_client.get(f"/acr/approvals/{request_id}")
        assert got.status_code == 200
        assert got.json()["status"] == "pending"

        execute = await async_client.post(f"/acr/approvals/{request_id}/execute", json={})
        assert execute.status_code in (403, 409)

        approved = await async_client.post(
            f"/acr/approvals/{request_id}/approve",
            json={"approver_id": "test-operator", "reason": "reviewed"},
        )
        assert approved.status_code == 200
        assert approved.json()["status"] == "approved"


# ── Observe report ────────────────────────────────────────────────────────────


class TestObserveReport:
    async def _seed(self, db: AsyncSession, agent_id: str) -> None:
        now = utcnow()
        rows = [
            # (decision, mode, tool, seq, age_days)
            ("deny", "observe", "issue_refund", 1, 1),
            ("deny", "observe", "issue_refund", 2, 1),
            ("escalate", "observe", "issue_refund", 3, 2),
            ("deny", "observe", "send_email", 4, 2),
            ("allow", "observe", "query_customer_db", 5, 3),
            ("allow", "observe", "query_customer_db", 6, 3),
            ("deny", "enforce", "issue_refund", 7, 1),  # must never be counted
            ("deny", "observe", "issue_refund", 8, 40),  # outside default window
        ]
        for decision, mode, tool, seq, age in rows:
            db.add(
                PolicyDecisionRecord(
                    correlation_id=f"corr-{agent_id}-{seq}",
                    agent_id=agent_id,
                    policy_id="acr-test",
                    decision=decision,
                    enforcement_mode=mode,
                    tool_name=tool,
                    sequence=seq,
                    created_at=now - timedelta(days=age),
                )
            )
        await db.commit()

    async def test_report_aggregates_only_observe_decisions(
        self, async_client: AsyncClient, db: AsyncSession
    ) -> None:
        await _register(db, "report-agent", mode="observe")
        await self._seed(db, "report-agent")
        resp = await async_client.get("/acr/agents/report-agent/observe-report")
        assert resp.status_code == 200
        data = resp.json()
        assert data["agent_id"] == "report-agent"
        assert data["enforcement_mode"] == "observe"
        assert data["total_decisions"] == 6
        assert data["counts_by_decision"] == {"deny": 3, "escalate": 1, "allow": 2}
        top = data["top_blocked_tools"]
        assert top[0]["tool_name"] == "issue_refund"
        assert top[0]["deny_count"] == 2
        assert top[0]["escalate_count"] == 1
        assert top[0]["blocking_total"] == 3
        assert {s["correlation_id"] for s in data["samples"]} >= {
            "corr-report-agent-1",
            "corr-report-agent-6",
        }
        assert all(not s["correlation_id"].endswith("-7") for s in data["samples"])

    async def test_report_window_filter(self, async_client: AsyncClient, db: AsyncSession) -> None:
        await _register(db, "report-window", mode="observe")
        await self._seed(db, "report-window")
        start = (utcnow() - timedelta(days=2, hours=12)).isoformat()
        end = utcnow().isoformat()
        resp = await async_client.get(
            "/acr/agents/report-window/observe-report",
            params={"window_start": start, "window_end": end},
        )
        assert resp.status_code == 200
        data = resp.json()
        # Only the rows aged 1-2 days fall inside the window.
        assert data["total_decisions"] == 4

    async def test_report_for_unknown_agent_is_404(self, async_client: AsyncClient) -> None:
        resp = await async_client.get("/acr/agents/nope/observe-report")
        assert resp.status_code == 404

    async def test_report_reflects_live_evaluations(
        self, async_client: AsyncClient, db: AsyncSession
    ) -> None:
        await _register(db, "report-live", mode="observe")
        with _patch_policy(DENY_RESULT):
            await async_client.post("/acr/evaluate", json=_body("report-live"))
        await async_client.post("/acr/evaluate", json=_body("report-live"))
        resp = await async_client.get("/acr/agents/report-live/observe-report")
        data = resp.json()
        assert data["total_decisions"] == 2
        assert data["counts_by_decision"] == {"deny": 1, "allow": 1}
        assert data["top_blocked_tools"][0]["tool_name"] == "query_customer_db"
