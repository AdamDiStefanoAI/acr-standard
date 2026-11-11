from __future__ import annotations

import hmac
import io
import zipfile
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from acr.common.errors import AuthoritativeSpendControlError
from acr.config import settings
from acr.db.models import TelemetryEventRecord
from acr.gateway.spend_control import resolve_action_cost_usd
from acr.pillar2_policy.engine import evaluate_policy
from acr.pillar2_policy.models import PolicyDecision, PolicyEvaluationResult
from acr.pillar4_observability.evidence import build_evidence_bundle
from acr.pillar4_observability.integrity import verify_event_chain
from acr.pillar4_observability.schema import LatencyBreakdown
from acr.pillar4_observability.telemetry import build_event, persist_event
from acr.pillar6_authority.approval import create_approval_request, execute_approval
from acr.policy_studio.core_bundle import core_identity, operator_identity


def _mock_opa_response(result: dict) -> AsyncMock:
    response = MagicMock()
    response.status_code = 200
    response.json.return_value = {
        "result": {
            **result,
            "core_identity": core_identity(),
            "operator_identity": operator_identity(),
        }
    }
    response.raise_for_status = MagicMock()
    response.request = MagicMock()

    client = AsyncMock()
    client.post = AsyncMock(return_value=response)
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=False)
    return client


class TestModifyDecision:
    async def test_policy_engine_returns_modify_with_transformed_parameters(self) -> None:
        client = _mock_opa_response(
            {
                "allow": False,
                "deny": [],
                "modify": True,
                "modified_parameters": {"customer_id": "C-001", "note": "[REDACTED]"},
            }
        )

        with patch("acr.pillar2_policy.engine.httpx.AsyncClient", return_value=client):
            result = await evaluate_policy(
                {"agent_id": "agent-1", "allowed_tools": ["query_customer_db"]},
                {
                    "tool_name": "query_customer_db",
                    "parameters": {"customer_id": "C-001", "note": "secret"},
                },
                {},
            )

        assert result.final_decision == "modify"
        assert result.modified_parameters == {"customer_id": "C-001", "note": "[REDACTED]"}
        assert result.decisions[0].decision == "modify"

    async def test_gateway_returns_modified_action_payload(
        self,
        async_client: AsyncClient,
        sample_agent,
    ) -> None:
        modify_result = PolicyEvaluationResult(
            final_decision="modify",
            decisions=[
                PolicyDecision(
                    policy_id="acr-modify", decision="modify", reason="Transform before release"
                )
            ],
            reason="Transform before release",
            modified_parameters={"customer_id": "C-001", "note": "[REDACTED]"},
            latency_ms=7,
        )

        with patch(
            "acr.gateway.router.evaluate_policy", new_callable=AsyncMock, return_value=modify_result
        ):
            response = await async_client.post(
                "/acr/evaluate",
                json={
                    "agent_id": sample_agent.agent_id,
                    "action": {
                        "tool_name": "query_customer_db",
                        "parameters": {"customer_id": "C-001", "note": "call me at 555-123-4567"},
                    },
                    "context": {},
                },
            )

        assert response.status_code == 200
        payload = response.json()
        assert payload["decision"] == "modify"
        assert payload["modified_action"]["tool_name"] == "query_customer_db"
        assert payload["modified_action"]["parameters"]["note"] == "[REDACTED]"

    async def test_gateway_denies_modify_that_changes_tool_name(
        self,
        async_client: AsyncClient,
        sample_agent,
    ) -> None:
        modify_result = PolicyEvaluationResult(
            final_decision="modify",
            decisions=[
                PolicyDecision(
                    policy_id="acr-modify", decision="modify", reason="Transform before release"
                )
            ],
            reason="Transform before release",
            modified_action={"tool_name": "send_email", "parameters": {}},
            latency_ms=5,
        )

        with patch(
            "acr.gateway.router.evaluate_policy", new_callable=AsyncMock, return_value=modify_result
        ):
            response = await async_client.post(
                "/acr/evaluate",
                json={
                    "agent_id": sample_agent.agent_id,
                    "action": {
                        "tool_name": "query_customer_db",
                        "parameters": {"customer_id": "C-001"},
                    },
                    "context": {},
                },
            )

        assert response.status_code == 403
        assert response.json()["error_code"] == "INVALID_MODIFY_DECISION"


class TestEvidenceIntegrity:
    async def test_persisted_events_form_a_signed_chain_and_bundle(
        self,
        db: AsyncSession,
        sample_agent,
    ) -> None:
        correlation_id = "corr-signed-bundle"

        for idx, tool_name in enumerate(("query_customer_db", "send_email"), start=1):
            event = build_event(
                event_type="ai_inference",
                agent_id=sample_agent.agent_id,
                agent_purpose=sample_agent.purpose,
                agent_capabilities=sample_agent.allowed_tools or [],
                correlation_id=correlation_id,
                session_id="sess-1",
                tool_name=tool_name,
                parameters={"step": idx},
                description=f"step {idx}",
                context={"session_id": "sess-1"},
                intent={"goal": "test integrity"},
                start_time="2026-03-17T00:00:00Z",
                end_time="2026-03-17T00:00:01Z",
                duration_ms=10,
                latency_breakdown=LatencyBreakdown(identity_ms=1, policy_ms=2, total_ms=3),
                policies=[],
                output_decision="allow",
                output_reason=None,
                approval_request_id=None,
                drift_score=0.1,
            )
            await persist_event(db, event)

        await db.commit()
        result = await db.execute(
            select(TelemetryEventRecord.payload)
            .where(TelemetryEventRecord.correlation_id == correlation_id)
            .order_by(TelemetryEventRecord.created_at.asc())
        )
        events = list(result.scalars().all())

        integrity = verify_event_chain(events)
        assert integrity["chain_valid"] is True
        assert integrity["verified_events"] == 2

        bundle = build_evidence_bundle(correlation_id=correlation_id, events=events)
        with zipfile.ZipFile(io.BytesIO(bundle.bytes_data)) as archive:
            names = set(archive.namelist())
            assert "bundle.signature" in names
            manifest_bytes = archive.read("manifest.json")
            events_bytes = archive.read("events.jsonl")
            signature = archive.read("bundle.signature").decode().strip()

        expected_signature = hmac.new(
            settings.audit_signing_secret.encode(),
            manifest_bytes + b"\n" + events_bytes,
            "sha256",
        ).hexdigest()
        assert signature == expected_signature


class TestSpendControls:
    def test_resolve_action_cost_prefers_tool_specific_boundaries(self) -> None:
        manifest = {
            "boundaries": {
                "default_action_cost_usd": 0.10,
                "tool_costs_usd": {"send_email": 0.02},
            }
        }

        assert resolve_action_cost_usd(manifest, "send_email") == 0.02
        assert resolve_action_cost_usd(manifest, "query_customer_db") == 0.10

    def test_resolve_action_cost_requires_authoritative_config_in_production(
        self, monkeypatch
    ) -> None:
        monkeypatch.setattr(settings, "acr_env", "production")
        with pytest.raises(AuthoritativeSpendControlError):
            resolve_action_cost_usd({"boundaries": {}}, "send_email")

    async def test_execute_approval_reserves_authoritative_spend(
        self,
        db: AsyncSession,
        sample_agent,
    ) -> None:
        record = await create_approval_request(
            db,
            correlation_id="corr-approval-spend",
            agent_id=sample_agent.agent_id,
            tool_name="issue_refund",
            parameters={"amount": 42},
            description="Refund approved by finance",
            approval_queue="finance",
            sla_minutes=60,
        )
        record.status = "approved"
        record.decided_by = "fixture-operator"
        await db.commit()

        # This unit test isolates spend charging; resumption checks are covered
        # end-to-end with safe fixtures in test_safe_approval_resume.py.
        with (
            patch(
                "acr.pillar6_authority.resumption.revalidate",
                new_callable=AsyncMock,
                return_value=({}, 0.25),
            ),
            patch(
                "acr.pillar6_authority.resumption.check_dispatch_boundary", new_callable=AsyncMock
            ),
            patch(
                "acr.pillar6_authority.approval.adjust_authoritative_spend", new_callable=AsyncMock
            ) as adjust_spend,
            patch(
                "acr.pillar6_authority.approval.execute_action",
                new_callable=AsyncMock,
                return_value={"status": "executed"},
            ),
        ):
            result = await execute_approval(db, record)

        assert result["status"] == "executed"
        adjust_spend.assert_awaited_once_with(sample_agent.agent_id, 0.25)
