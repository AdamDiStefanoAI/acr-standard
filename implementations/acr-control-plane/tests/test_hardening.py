"""Hardening pass tests (v1.4.0).

Covers the fixes driven by the Nov 8 red-team recon leads and the §18
ordering clarification (acr-standard PR #56):

- decision sequence assigned at issuance and decisions recorded durably
  before the response (§11/§18)
- fail-closed posture for Redis-backed controls unless degraded mode is
  explicitly opted into
- token-issuance rate limit fails closed
- brokered executor credentials bound to the execution payload hash
- tool-name canonicalization before policy matching
- drift check cadence and baseline floor
- approval binding (payload hash + expiry), verified as already enforced
  by the resumption/receipts machinery
"""

from __future__ import annotations

from datetime import timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import jwt
import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker

from acr.common.errors import ApprovalConflictError, InvalidExecutionAuthorizationError
from acr.common.time import utcnow
from acr.config import (
    assert_production_secrets,
    runtime_dependencies_fail_closed,
    settings,
)
from acr.db.models import PolicyDecisionRecord
from acr.gateway.executor_auth import (
    build_brokered_execution_credential,
    execution_payload_sha256,
    verify_brokered_execution_credential,
)
from acr.pillar2_policy.engine import canonical_tool_name, evaluate_policy
from acr.pillar2_policy.models import PolicyDecision, PolicyEvaluationResult
from acr.pillar3_drift.signals import MIN_BASELINE_SAMPLES
from acr.pillar6_authority import resumption
from acr.pillar6_authority.approval import create_approval_request
from acr.policy_studio.core_bundle import core_identity, operator_identity

_PAYLOAD = {"tool_name": "query_customer_db", "parameters": {"customer_id": "C-001"}}


def _evaluate_body(agent_id: str) -> dict:
    return {
        "agent_id": agent_id,
        "action": {"tool_name": "query_customer_db", "parameters": {"customer_id": "C-001"}},
        "context": {"session_id": "sess-hardening"},
    }


async def _decision_records(test_engine, agent_id: str) -> list[PolicyDecisionRecord]:
    factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    async with factory() as session:
        result = await session.execute(
            select(PolicyDecisionRecord)
            .where(PolicyDecisionRecord.agent_id == agent_id)
            .order_by(PolicyDecisionRecord.sequence)
        )
        return list(result.scalars().all())


# ── §18 decision sequence + durable recording ─────────────────────────────────


class TestDecisionRecording:
    async def test_decisions_recorded_synchronously_with_issuance_sequence(
        self, async_client: AsyncClient, sample_agent, test_engine
    ) -> None:
        resp1 = await async_client.post("/acr/evaluate", json=_evaluate_body(sample_agent.agent_id))
        resp2 = await async_client.post("/acr/evaluate", json=_evaluate_body(sample_agent.agent_id))
        assert resp1.status_code == 200
        assert resp2.status_code == 200

        records = await _decision_records(test_engine, sample_agent.agent_id)
        assert len(records) == 2
        # Sequences are assigned at issuance, in order, starting at 1.
        assert [r.sequence for r in records] == [1, 2]
        assert all(r.decision == "allow" for r in records)

    async def test_deny_is_recorded_before_the_response_returns(
        self, async_client: AsyncClient, sample_agent, test_engine
    ) -> None:
        deny_result = PolicyEvaluationResult(
            final_decision="deny",
            decisions=[PolicyDecision(policy_id="acr-deny-0", decision="deny", reason="blocked")],
            reason="blocked",
            latency_ms=3,
        )
        with patch(
            "acr.gateway.router.evaluate_policy",
            new_callable=AsyncMock,
            return_value=deny_result,
        ):
            resp = await async_client.post(
                "/acr/evaluate", json=_evaluate_body(sample_agent.agent_id)
            )
        assert resp.status_code == 403
        # No background flush to wait for: the record already exists.
        records = await _decision_records(test_engine, sample_agent.agent_id)
        assert len(records) == 1
        assert records[0].decision == "deny"
        assert records[0].sequence == 1

    async def test_recording_failure_fails_secure(
        self, async_client: AsyncClient, sample_agent
    ) -> None:
        with patch(
            "acr.gateway.router._record_policy_decisions",
            new_callable=AsyncMock,
            side_effect=RuntimeError("db down"),
        ):
            resp = await async_client.post(
                "/acr/evaluate", json=_evaluate_body(sample_agent.agent_id)
            )
        assert resp.status_code == 503
        data = resp.json()
        assert data["decision"] == "deny"
        assert data["error_code"] == "EVIDENCE_PERSISTENCE_FAILED"


# ── Fail-closed posture ───────────────────────────────────────────────────────


class TestFailClosedPosture:
    def test_fail_closed_by_default(self, monkeypatch) -> None:
        monkeypatch.setattr(settings, "allow_degraded_dependencies", False)
        assert runtime_dependencies_fail_closed() is True

    def test_degraded_mode_is_explicit_opt_in(self, monkeypatch) -> None:
        monkeypatch.setattr(settings, "allow_degraded_dependencies", True)
        assert runtime_dependencies_fail_closed() is False

    def test_degraded_mode_refused_outside_development(self, monkeypatch) -> None:
        monkeypatch.setattr(settings, "acr_env", "production")
        monkeypatch.setattr(settings, "allow_degraded_dependencies", True)
        with pytest.raises(RuntimeError, match="ALLOW_DEGRADED_DEPENDENCIES"):
            assert_production_secrets()

    async def test_evaluate_fails_closed_when_redis_unavailable(
        self, async_client: AsyncClient, sample_agent, monkeypatch
    ) -> None:
        # The async_client fixture opts into degraded mode because tests run
        # without Redis; turning the opt-in off must fail the evaluation
        # closed instead of silently dropping containment and rate limits.
        monkeypatch.setattr(settings, "allow_degraded_dependencies", False)
        resp = await async_client.post("/acr/evaluate", json=_evaluate_body(sample_agent.agent_id))
        assert resp.status_code == 503
        data = resp.json()
        assert data["decision"] == "deny"
        assert data["error_code"] == "RUNTIME_CONTROL_DEPENDENCY_ERROR"

    async def test_token_issuance_fails_closed_when_redis_unavailable(
        self, async_client: AsyncClient, sample_agent, monkeypatch
    ) -> None:
        monkeypatch.setattr(settings, "allow_degraded_dependencies", False)
        resp = await async_client.post(f"/acr/agents/{sample_agent.agent_id}/token")
        assert resp.status_code == 503


# ── Tool-name canonicalization ────────────────────────────────────────────────


def _capturing_opa_client(captured: dict):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "result": {
            "allow": True,
            "deny": [],
            "core_identity": core_identity(),
            "operator_identity": operator_identity(),
        }
    }
    mock_resp.raise_for_status = MagicMock()
    mock_resp.request = MagicMock()

    async def capture_post(path, json=None, **kwargs):
        captured.update(json or {})
        return mock_resp

    mock_client = AsyncMock()
    mock_client.post = AsyncMock(side_effect=capture_post)
    return mock_client


class TestToolNameCanonicalization:
    def test_canonical_form(self) -> None:
        assert canonical_tool_name(" Send_Email ") == "send_email"
        assert canonical_tool_name("QUERY_CUSTOMER_DB") == "query_customer_db"

    async def test_opa_input_uses_canonical_names_on_both_sides(self) -> None:
        captured: dict = {}
        client = _capturing_opa_client(captured)
        manifest = {
            "agent_id": "agent-1",
            "allowed_tools": ["Send_Email", " query_customer_db"],
            "forbidden_tools": ["Delete_Customer"],
        }
        action = {"tool_name": " SEND_EMAIL ", "parameters": {}}
        with patch("acr.pillar2_policy.engine.httpx.AsyncClient", return_value=client):
            result = await evaluate_policy(manifest, action, {})
        assert result.final_decision == "allow"
        sent = captured["input"]
        assert sent["action"]["tool_name"] == "send_email"
        assert sent["agent"]["allowed_tools"] == ["send_email", "query_customer_db"]
        assert sent["agent"]["forbidden_tools"] == ["delete_customer"]


# ── Brokered credential payload binding ───────────────────────────────────────


class TestBrokeredCredentialBinding:
    def test_credential_is_bound_to_payload(self, monkeypatch) -> None:
        monkeypatch.setattr(settings, "executor_credential_secret", "c" * 64)
        credential = build_brokered_execution_credential(
            agent_id="agent-1",
            tool_name="query_customer_db",
            correlation_id="corr-1",
            audience="tool:query_customer_db",
            scopes=["execute"],
            payload=_PAYLOAD,
        )
        verified = verify_brokered_execution_credential(
            credential, audience="tool:query_customer_db", payload=_PAYLOAD
        )
        assert verified.payload_sha256 == execution_payload_sha256(_PAYLOAD)
        with pytest.raises(InvalidExecutionAuthorizationError):
            verify_brokered_execution_credential(
                credential,
                audience="tool:query_customer_db",
                payload={"tool_name": "query_customer_db", "parameters": {"customer_id": "C-999"}},
            )

    def test_unbound_legacy_credential_rejected_on_payload_path(self, monkeypatch) -> None:
        secret = "c" * 64
        monkeypatch.setattr(settings, "executor_credential_secret", secret)
        # A credential minted before payload binding existed: same claims,
        # no payload_sha256. It must not be replayable against any payload.
        legacy = jwt.encode(
            {
                "iss": "acr-control-plane",
                "sub": "acr-executor:agent-1:query_customer_db",
                "agent_id": "agent-1",
                "tool_name": "query_customer_db",
                "correlation_id": "corr-1",
                "aud": "tool:query_customer_db",
                "scopes": ["execute"],
                "exp": 9999999999,
            },
            secret,
            algorithm="HS256",
        )
        with pytest.raises(InvalidExecutionAuthorizationError, match="not bound to a payload"):
            verify_brokered_execution_credential(
                legacy, audience="tool:query_customer_db", payload=_PAYLOAD
            )


# ── Drift cadence / baseline ──────────────────────────────────────────────────


class TestDriftCadence:
    async def test_drift_check_runs_on_first_evaluation_by_default(self) -> None:
        from acr.gateway.router import _should_run_drift_check

        with patch("acr.gateway.router.get_redis_or_none", return_value=None):
            assert await _should_run_drift_check("agent-1") is True

    def test_baseline_floor(self) -> None:
        assert MIN_BASELINE_SAMPLES == 10


# ── Approval binding (already enforced; pinned here against regression) ──────


class TestApprovalBinding:
    async def test_tampered_approval_payload_is_rejected(self, db, sample_agent) -> None:
        record = await create_approval_request(
            db,
            correlation_id="corr-hardening",
            agent_id=sample_agent.agent_id,
            tool_name="issue_refund",
            parameters={"amount": 25},
            description="refund",
            approval_queue="default",
            sla_minutes=60,
        )
        await db.commit()
        resumption.check_request(record)  # untampered: passes

        record.parameters = {"amount": 2500}  # substituted after the request
        with pytest.raises(ApprovalConflictError):
            resumption.check_request(record)

    async def test_expired_approval_is_rejected(self, db, sample_agent) -> None:
        record = await create_approval_request(
            db,
            correlation_id="corr-hardening-expired",
            agent_id=sample_agent.agent_id,
            tool_name="issue_refund",
            parameters={"amount": 25},
            description="refund",
            approval_queue="default",
            sla_minutes=60,
        )
        await db.commit()
        record.expires_at = utcnow() - timedelta(minutes=1)
        with pytest.raises(ApprovalConflictError):
            resumption.check_request(record)
