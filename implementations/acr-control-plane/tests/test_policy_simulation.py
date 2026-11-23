"""Policy simulation tests (v1.5.0 WS2).

WS2 adds opt-in evaluation-input retention (redacted before storage,
purged on expiry), an offline replay engine that diffs a candidate
bundle against recorded decisions, a durable simulation report with
API/CLI surfaces, and a promotion gate on release activation.

The invariants under test:
- retention OFF changes nothing: no input rows, evaluate path untouched
- retention ON stores the effective input redacted; the canary value
  appears nowhere — not in the stored row, not in any report or export
- retention rides the decision-recording transaction: if the input
  write fails, the recording fails exactly like a decision-write
  failure (the gateway's fail-secure 503 path is unchanged)
- replay against the shipping bundle reproduces recorded decisions
  exactly; a tightened bundle produces exactly the expected flips
- windows with purged/never-retained inputs report the coverage gap
- purge deletes payloads only; decision records survive
- simulations create no approvals, no telemetry, no decision rows
- the activation gate binds only when retention is on
"""

from __future__ import annotations

import json
import subprocess
from datetime import timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from acr.common.errors import PolicyValidationError
from acr.common.operator_auth import OperatorPrincipal, get_operator_principal
from acr.common.time import utcnow
from acr.config import evaluation_input_redaction_fields, settings
from acr.db.models import (
    ApprovalRequestRecord,
    EvaluationInputRecord,
    PolicyDecisionRecord,
    PolicyReleaseRecord,
    PolicySimulationRecord,
    TelemetryEventRecord,
)
from acr.gateway.router import _record_policy_decisions
from acr.main import app
from acr.pillar1_identity.models import AgentRegisterRequest
from acr.pillar1_identity.registry import get_manifest, register_agent
from acr.pillar2_policy.simulation import run_simulation
from acr.pillar4_observability.input_retention import (
    REDACTED_MARKER,
    build_retained_input_data,
    canonical_payload_hash,
    purge_expired_inputs,
    redact_payload,
)
from acr.policy_studio.distribution import build_active_runtime_bundle
from acr.policy_studio.releases import activate_policy_release

CANARY = "CANARY-SECRET-98765"
AGENT = "sim-agent"
ALLOWED = ["query_customer_db", "send_email", "issue_refund"]


@pytest.fixture
def retention_on(monkeypatch):
    monkeypatch.setattr(settings, "evaluation_input_retention_enabled", True)
    evaluation_input_redaction_fields.cache_clear()
    yield
    evaluation_input_redaction_fields.cache_clear()


async def _register(db: AsyncSession, agent_id: str = AGENT):
    record = await register_agent(
        db,
        AgentRegisterRequest(
            agent_id=agent_id,
            owner="simulation-tests@example.com",
            purpose="Policy simulation test agent",
            allowed_tools=ALLOWED,
            forbidden_tools=["delete_customer"],
        ),
    )
    await db.commit()
    return record


def _evaluation_input(manifest: dict, tool_name: str, parameters: dict | None = None) -> dict:
    return {
        "agent": manifest,
        "action": {"tool_name": tool_name, "parameters": parameters or {}},
        "context": {"actions_this_minute": 0, "hourly_spend_usd": 0.0, "session_id": "s-1"},
    }


async def _seed_evaluation(
    db: AsyncSession,
    *,
    manifest: dict,
    correlation_id: str,
    tool_name: str,
    decision: str,
    when,
    retain: bool = True,
    purged: bool = False,
    parameters: dict | None = None,
    sequence: int = 1,
) -> None:
    """Write one evaluation exactly as the gateway would have recorded it:
    a decision row plus (optionally) its retained input."""
    db.add(
        PolicyDecisionRecord(
            correlation_id=correlation_id,
            agent_id=AGENT,
            policy_id=f"acr-{decision}-0",
            decision=decision,
            enforcement_mode="enforce",
            reason="seeded",
            tool_name=tool_name,
            latency_ms=1,
            sequence=sequence,
            created_at=when,
        )
    )
    if retain:
        payload = _evaluation_input(manifest, tool_name, parameters)
        db.add(
            EvaluationInputRecord(
                correlation_id=correlation_id,
                agent_id=AGENT,
                payload=None if purged else payload,
                payload_sha256=canonical_payload_hash(payload),
                recorded_decision=decision,
                enforcement_mode="enforce",
                state="purged" if purged else "retained",
                retained_at=when,
                expires_at=when + timedelta(days=30),
                purged_at=when if purged else None,
            )
        )
    await db.commit()


async def _count(test_engine, model, **filters) -> int:
    factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    async with factory() as session:
        query = select(func.count()).select_from(model)
        for key, value in filters.items():
            query = query.where(getattr(model, key) == value)
        result = await session.execute(query)
        return int(result.scalar_one())


def _window():
    now = utcnow()
    return now - timedelta(hours=2), now + timedelta(hours=1)


def _shipping_bundle_bytes() -> bytes:
    return build_active_runtime_bundle([]).bytes_data


# ── Redaction ─────────────────────────────────────────────────────────────────


class TestRedaction:
    def test_redact_replaces_configured_paths_only(self) -> None:
        payload = {
            "agent": {"agent_id": "a"},
            "action": {"tool_name": "t", "parameters": {"customer_id": CANARY, "q": "x"}},
            "context": {"api_key": CANARY, "session_id": "s"},
        }
        redacted = redact_payload(payload, ["action.parameters.customer_id", "context.api_key"])
        assert redacted["action"]["parameters"]["customer_id"] == REDACTED_MARKER
        assert redacted["context"]["api_key"] == REDACTED_MARKER
        assert redacted["action"]["parameters"]["q"] == "x"
        assert redacted["context"]["session_id"] == "s"
        # The original is never mutated.
        assert payload["action"]["parameters"]["customer_id"] == CANARY

    def test_redact_missing_paths_are_noops(self) -> None:
        payload = {"action": {"parameters": {}}}
        assert redact_payload(payload, ["action.parameters.nope", "context.api_key"]) == payload

    def test_build_retained_input_data_redacts_and_hashes(self) -> None:
        data = build_retained_input_data(
            correlation_id="c-1",
            agent_id=AGENT,
            evaluation_input=_evaluation_input({"agent_id": AGENT}, "t", {"customer_id": CANARY}),
            recorded_decision="allow",
            enforcement_mode="enforce",
            redaction_fields=["action.parameters.customer_id"],
        )
        assert CANARY not in json.dumps(data["payload"])
        assert data["payload"]["action"]["parameters"]["customer_id"] == REDACTED_MARKER
        assert data["payload_sha256"] == canonical_payload_hash(data["payload"])
        assert data["expires_at"] > data["retained_at"]


# ── Retention at the gateway ──────────────────────────────────────────────────


class TestGatewayRetention:
    async def test_retention_off_writes_no_input_rows(
        self, async_client: AsyncClient, db: AsyncSession, test_engine
    ) -> None:
        assert settings.evaluation_input_retention_enabled is False
        await _register(db)
        resp = await async_client.post(
            "/acr/evaluate",
            json={
                "agent_id": AGENT,
                "action": {"tool_name": "query_customer_db", "parameters": {"customer_id": "C-1"}},
                "context": {"session_id": "s-off"},
            },
        )
        assert resp.status_code == 200
        assert await _count(test_engine, EvaluationInputRecord) == 0
        assert await _count(test_engine, PolicyDecisionRecord, agent_id=AGENT) >= 1

    async def test_retention_on_stores_redacted_input(
        self,
        async_client: AsyncClient,
        db: AsyncSession,
        test_engine,
        retention_on,
        monkeypatch,
    ) -> None:
        monkeypatch.setattr(
            settings,
            "evaluation_input_redaction_fields_json",
            '["action.parameters.customer_id"]',
        )
        evaluation_input_redaction_fields.cache_clear()
        await _register(db)
        resp = await async_client.post(
            "/acr/evaluate",
            json={
                "agent_id": AGENT,
                "action": {"tool_name": "query_customer_db", "parameters": {"customer_id": CANARY}},
                "context": {"session_id": "s-on"},
            },
        )
        assert resp.status_code == 200
        factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
        async with factory() as session:
            rows = (await session.execute(select(EvaluationInputRecord))).scalars().all()
        assert len(rows) == 1
        row = rows[0]
        assert row.state == "retained"
        assert row.recorded_decision == "allow"
        assert row.payload["action"]["parameters"]["customer_id"] == REDACTED_MARKER
        assert CANARY not in json.dumps(row.payload)
        # The retained input is the effective input: manifest + enriched context.
        assert row.payload["agent"]["agent_id"] == AGENT
        assert "actions_this_minute" in row.payload["context"]

    async def test_retention_write_failure_fails_the_recording(
        self, db: AsyncSession, test_engine
    ) -> None:
        """The retained input rides the recording transaction: a colliding
        retention write rolls the decision rows back with it, which is the
        gateway's fail-secure path (503 EVIDENCE_PERSISTENCE_FAILED)."""
        await _register(db)
        manifest = (await get_manifest(db, AGENT)).model_dump(mode="json")
        when = utcnow()
        await _seed_evaluation(
            db,
            manifest=manifest,
            correlation_id="tx-collision",
            tool_name="query_customer_db",
            decision="allow",
            when=when,
        )
        colliding = build_retained_input_data(
            correlation_id="tx-collision",
            agent_id=AGENT,
            evaluation_input=_evaluation_input(manifest, "query_customer_db"),
            recorded_decision="allow",
            enforcement_mode="enforce",
            redaction_fields=[],
        )
        with pytest.raises(IntegrityError):
            await _record_policy_decisions(
                db,
                agent_id=AGENT,
                correlation_id="tx-collision",
                tool_name="query_customer_db",
                decisions=[{"policy_id": "acr-allow", "decision": "allow"}],
                retained_input_data=colliding,
            )
        # Only the seeded decision row exists; the failed recording added none.
        assert await _count(test_engine, PolicyDecisionRecord, correlation_id="tx-collision") == 1


# ── Replay fidelity and flips ─────────────────────────────────────────────────


class TestReplay:
    async def _seed_traffic(self, db: AsyncSession) -> dict:
        await _register(db)
        manifest = (await get_manifest(db, AGENT)).model_dump(mode="json")
        when = utcnow() - timedelta(minutes=30)
        cases = [
            ("sim-allow", "query_customer_db", "allow"),
            ("sim-forbidden", "delete_customer", "deny"),
            ("sim-unauthorized", "unknown_tool", "deny"),
            ("sim-email", "send_email", "allow"),
        ]
        for index, (cid, tool, decision) in enumerate(cases, start=1):
            await _seed_evaluation(
                db,
                manifest=manifest,
                correlation_id=cid,
                tool_name=tool,
                decision=decision,
                when=when,
                sequence=index,
                parameters={"customer_id": CANARY} if tool == "query_customer_db" else None,
            )
        return manifest

    async def test_shipping_bundle_replay_has_zero_flips(self, db: AsyncSession) -> None:
        await self._seed_traffic(db)
        start, end = _window()
        record = await run_simulation(
            db,
            actor="test",
            window_start=start,
            window_end=end,
            bundle_bytes=_shipping_bundle_bytes(),
            bundle_label="shipping",
        )
        await db.commit()
        report = record.report
        assert report["decisions_in_window"] == 4
        assert report["inputs_available"] == 4
        assert report["inputs_missing"] == 0
        assert report["unchanged_count"] == 4
        assert report["flip_counts"] == {}
        assert report["result_hash"] == record.result_hash

    async def test_tightened_bundle_flips_exactly_the_expected_cases(
        self, db: AsyncSession
    ) -> None:
        from acr.pillar2_policy.simulation import build_candidate_bundle

        await self._seed_traffic(db)
        artifact = await build_candidate_bundle(
            db,
            agent_id=AGENT,
            rego_policy=(
                "package acr\n"
                "deny contains reason if {\n"
                '    input.action.tool_name == "send_email"\n'
                '    reason := "send_email disabled by tightened policy"\n'
                "}"
            ),
        )
        start, end = _window()
        record = await run_simulation(
            db,
            actor="test",
            window_start=start,
            window_end=end,
            bundle_bytes=artifact.bytes_data,
            bundle_label="tightened",
        )
        await db.commit()
        report = record.report
        assert report["flip_counts"] == {"allow->deny": 1}
        assert report["flips_by_rule"] == {"send_email disabled by tightened policy": 1}
        assert report["unchanged_count"] == 3
        assert len(report["samples"]) == 1
        sample = report["samples"][0]
        assert sample["correlation_id"] == "sim-email"
        assert sample["recorded_decision"] == "allow"
        assert sample["simulated_decision"] == "deny"

    async def test_escalation_flip_is_reported(self, db: AsyncSession) -> None:
        from acr.pillar2_policy.simulation import build_candidate_bundle

        await self._seed_traffic(db)
        artifact = await build_candidate_bundle(
            db,
            agent_id=AGENT,
            rego_policy=(
                'package acr\nescalate if {\n    input.action.tool_name == "issue_refund"\n}'
            ),
        )
        # issue_refund was not in the seeded traffic; seed one allow for it.
        manifest = (await get_manifest(db, AGENT)).model_dump(mode="json")
        await _seed_evaluation(
            db,
            manifest=manifest,
            correlation_id="sim-refund",
            tool_name="issue_refund",
            decision="allow",
            when=utcnow() - timedelta(minutes=10),
            sequence=9,
        )
        start, end = _window()
        record = await run_simulation(
            db,
            actor="test",
            window_start=start,
            window_end=end,
            bundle_bytes=artifact.bytes_data,
            bundle_label="escalating",
        )
        report = record.report
        assert report["flip_counts"] == {"allow->escalate": 1}

    async def test_simulation_creates_no_live_side_effects(
        self, db: AsyncSession, test_engine
    ) -> None:
        await self._seed_traffic(db)
        before = {
            "approvals": await _count(test_engine, ApprovalRequestRecord),
            "telemetry": await _count(test_engine, TelemetryEventRecord),
            "decisions": await _count(test_engine, PolicyDecisionRecord),
            "inputs": await _count(test_engine, EvaluationInputRecord),
            "simulations": await _count(test_engine, PolicySimulationRecord),
        }
        start, end = _window()
        await run_simulation(
            db,
            actor="test",
            window_start=start,
            window_end=end,
            bundle_bytes=_shipping_bundle_bytes(),
            bundle_label="shipping",
        )
        await db.commit()
        after = {
            "approvals": await _count(test_engine, ApprovalRequestRecord),
            "telemetry": await _count(test_engine, TelemetryEventRecord),
            "decisions": await _count(test_engine, PolicyDecisionRecord),
            "inputs": await _count(test_engine, EvaluationInputRecord),
            "simulations": await _count(test_engine, PolicySimulationRecord),
        }
        assert after["approvals"] == before["approvals"]
        assert after["telemetry"] == before["telemetry"]
        assert after["decisions"] == before["decisions"]
        assert after["inputs"] == before["inputs"]
        assert after["simulations"] == before["simulations"] + 1


# ── Coverage honesty and purge ────────────────────────────────────────────────


class TestCoverageAndPurge:
    async def test_purged_inputs_report_as_coverage_gap(self, db: AsyncSession) -> None:
        await _register(db)
        manifest = (await get_manifest(db, AGENT)).model_dump(mode="json")
        when = utcnow() - timedelta(minutes=30)
        await _seed_evaluation(
            db,
            manifest=manifest,
            correlation_id="cov-1",
            tool_name="query_customer_db",
            decision="allow",
            when=when,
            sequence=1,
        )
        await _seed_evaluation(
            db,
            manifest=manifest,
            correlation_id="cov-2",
            tool_name="query_customer_db",
            decision="allow",
            when=when,
            sequence=2,
            purged=True,
        )
        await _seed_evaluation(
            db,
            manifest=manifest,
            correlation_id="cov-3",
            tool_name="query_customer_db",
            decision="allow",
            when=when,
            sequence=3,
            retain=False,
        )
        start, end = _window()
        record = await run_simulation(
            db,
            actor="test",
            window_start=start,
            window_end=end,
            bundle_bytes=_shipping_bundle_bytes(),
            bundle_label="shipping",
        )
        report = record.report
        assert report["decisions_in_window"] == 3
        assert report["inputs_available"] == 1
        assert report["inputs_missing"] == 2
        assert report["evaluations_replayed"] == 1

    async def test_purge_deletes_payload_and_keeps_decisions(
        self, db: AsyncSession, test_engine
    ) -> None:
        await _register(db)
        manifest = (await get_manifest(db, AGENT)).model_dump(mode="json")
        when = utcnow() - timedelta(days=45)
        await _seed_evaluation(
            db,
            manifest=manifest,
            correlation_id="purge-1",
            tool_name="query_customer_db",
            decision="allow",
            when=when,
            sequence=1,
        )
        # Backdate the expiry so the row is purgeable.
        factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
        async with factory() as session:
            row = (
                await session.execute(
                    select(EvaluationInputRecord).where(
                        EvaluationInputRecord.correlation_id == "purge-1"
                    )
                )
            ).scalar_one()
            row.expires_at = utcnow() - timedelta(days=1)
            await session.commit()

        async with factory() as session:
            purged = await purge_expired_inputs(session)
            await session.commit()
            assert purged == 1
            row = (
                await session.execute(
                    select(EvaluationInputRecord).where(
                        EvaluationInputRecord.correlation_id == "purge-1"
                    )
                )
            ).scalar_one()
            assert row.payload is None
            assert row.state == "purged"
            assert row.purged_at is not None
            # Idempotent.
            assert await purge_expired_inputs(session) == 0
        # The decision record is untouched.
        assert await _count(test_engine, PolicyDecisionRecord, correlation_id="purge-1") == 1


# ── Promotion gate + API surface ──────────────────────────────────────────────

DRAFT_BODY = {
    "name": "Simulation gate draft",
    "agent_id": "gate-bot-01",
    "template": "customer_support",
    "manifest": {
        "agent_id": "gate-bot-01",
        "owner": "ops@example.com",
        "purpose": "Exercise the simulation gate",
        "risk_tier": "medium",
        "allowed_tools": ["query_customer_db"],
        "forbidden_tools": ["delete_customer"],
        "boundaries": {"max_actions_per_minute": 30, "max_cost_per_hour_usd": 5.0},
    },
    "rego_policy": 'package acr\nescalate if {\n    input.action.tool_name == "issue_refund"\n}',
    "wizard_inputs": {"template": "customer_support"},
}

WIDE_WINDOW = {"window_start": "2026-01-01T00:00:00Z", "window_end": "2030-01-01T00:00:00Z"}


async def _publish(async_client: AsyncClient, body: dict | None = None) -> str:
    create_resp = await async_client.post("/acr/policy-drafts", json=body or DRAFT_BODY)
    assert create_resp.status_code == 201
    draft_id = create_resp.json()["draft_id"]
    publish_resp = await async_client.post(
        f"/acr/policy-drafts/{draft_id}/publish", json={"notes": "gate test"}
    )
    assert publish_resp.status_code == 201
    return publish_resp.json()["release_id"]


class TestPromotionGate:
    async def test_gate_inert_when_retention_off(self, async_client: AsyncClient) -> None:
        release_id = await _publish(async_client)
        resp = await async_client.post(f"/acr/policy-drafts/releases/{release_id}/activate")
        assert resp.status_code == 200
        assert resp.json()["activation_status"] == "active"
        assert resp.json()["simulation_report_id"] is None

    async def test_gate_blocks_and_then_allows_with_matching_report(
        self, async_client: AsyncClient, retention_on
    ) -> None:
        release_id = await _publish(async_client)

        blocked = await async_client.post(f"/acr/policy-drafts/releases/{release_id}/activate")
        assert blocked.status_code == 422
        assert "simulation" in blocked.json()["message"].lower()

        run_resp = await async_client.post(
            "/acr/policy-simulations", json={"release_id": release_id, **WIDE_WINDOW}
        )
        assert run_resp.status_code == 201
        run_id = run_resp.json()["run_id"]

        allowed = await async_client.post(
            f"/acr/policy-drafts/releases/{release_id}/activate",
            json={"simulation_report_id": run_id},
        )
        assert allowed.status_code == 200
        assert allowed.json()["activation_status"] == "active"
        assert allowed.json()["simulation_report_id"] == run_id

    async def test_gate_rejects_report_for_a_different_bundle(
        self, async_client: AsyncClient, retention_on
    ) -> None:
        release_id = await _publish(async_client)
        other_body = dict(DRAFT_BODY)
        other_body["agent_id"] = "gate-bot-02"
        other_body["manifest"] = {**DRAFT_BODY["manifest"], "agent_id": "gate-bot-02"}
        other_body["rego_policy"] = "package acr\nallow if { true }"
        other_release_id = await _publish(async_client, other_body)

        run_resp = await async_client.post(
            "/acr/policy-simulations", json={"release_id": other_release_id, **WIDE_WINDOW}
        )
        assert run_resp.status_code == 201
        foreign_run_id = run_resp.json()["run_id"]

        resp = await async_client.post(
            f"/acr/policy-drafts/releases/{release_id}/activate",
            json={"simulation_report_id": foreign_run_id},
        )
        assert resp.status_code == 422
        assert "not the bundle being activated" in resp.json()["message"]

    async def test_gate_off_allows_activation_without_report(
        self, async_client: AsyncClient, retention_on, monkeypatch
    ) -> None:
        monkeypatch.setattr(settings, "policy_simulation_gate_enabled", False)
        release_id = await _publish(async_client)
        resp = await async_client.post(f"/acr/policy-drafts/releases/{release_id}/activate")
        assert resp.status_code == 200

    async def test_service_level_gate_raises(self, db: AsyncSession, retention_on) -> None:
        record = PolicyReleaseRecord(
            release_id="rel-gate-service",
            draft_id="pdr-gate-service",
            agent_id="gate-service-agent",
            version=1,
            name="Gate service",
            template="customer_support",
            manifest=DRAFT_BODY["manifest"],
            rego_policy=DRAFT_BODY["rego_policy"],
            status="published",
            activation_status="inactive",
        )
        db.add(record)
        await db.commit()
        with pytest.raises(PolicyValidationError, match="simulation"):
            await activate_policy_release(db, release_id="rel-gate-service", actor="test")


class TestSimulationAPI:
    async def test_run_fetch_and_summary(self, async_client: AsyncClient) -> None:
        release_id = await _publish(async_client)
        run_resp = await async_client.post(
            "/acr/policy-simulations", json={"release_id": release_id, **WIDE_WINDOW}
        )
        assert run_resp.status_code == 201
        report = run_resp.json()
        assert report["bundle_label"] == release_id
        assert len(report["bundle_sha256"]) == 64
        assert len(report["result_hash"]) == 64
        run_id = report["run_id"]

        fetch_resp = await async_client.get(f"/acr/policy-simulations/{run_id}")
        assert fetch_resp.status_code == 200
        assert fetch_resp.json()["run_id"] == run_id

        summary_resp = await async_client.get(f"/acr/policy-simulations/{run_id}/summary.md")
        assert summary_resp.status_code == 200
        assert run_id in summary_resp.text
        assert "Coverage" in summary_resp.text

    async def test_unknown_run_is_404(self, async_client: AsyncClient) -> None:
        resp = await async_client.get("/acr/policy-simulations/sim-does-not-exist")
        assert resp.status_code == 404

    async def test_auditor_can_read_but_not_run(self, async_client: AsyncClient) -> None:
        release_id = await _publish(async_client)
        run_resp = await async_client.post(
            "/acr/policy-simulations", json={"release_id": release_id, **WIDE_WINDOW}
        )
        run_id = run_resp.json()["run_id"]
        app.dependency_overrides[get_operator_principal] = lambda: OperatorPrincipal(
            subject="auditor-only", roles=frozenset({"auditor"})
        )
        try:
            run_again = await async_client.post(
                "/acr/policy-simulations", json={"release_id": release_id, **WIDE_WINDOW}
            )
            assert run_again.status_code == 403
            fetch_resp = await async_client.get(f"/acr/policy-simulations/{run_id}")
            assert fetch_resp.status_code == 200
        finally:
            app.dependency_overrides[get_operator_principal] = lambda: OperatorPrincipal(
                subject="test-operator",
                roles=frozenset({"agent_admin", "approver", "security_admin", "auditor"}),
            )

    async def test_canary_never_reaches_report_or_exports(self, db: AsyncSession) -> None:
        """Seed through the real retention builder (redaction applied),
        force the case into the report's flipped samples — the worst case
        for leakage — and check the JSON report and the Markdown export."""
        from acr.pillar2_policy.simulation import build_candidate_bundle, render_markdown_summary

        await _register(db)
        manifest = (await get_manifest(db, AGENT)).model_dump(mode="json")
        when = utcnow()
        data = build_retained_input_data(
            correlation_id="canary-1",
            agent_id=AGENT,
            evaluation_input=_evaluation_input(manifest, "send_email", {"customer_id": CANARY}),
            recorded_decision="allow",
            enforcement_mode="enforce",
            now=when,
            redaction_fields=["action.parameters.customer_id"],
        )
        db.add(EvaluationInputRecord(**data))
        db.add(
            PolicyDecisionRecord(
                correlation_id="canary-1",
                agent_id=AGENT,
                policy_id="acr-allow",
                decision="allow",
                enforcement_mode="enforce",
                reason="seeded",
                tool_name="send_email",
                latency_ms=1,
                sequence=1,
                created_at=when,
            )
        )
        await db.commit()

        artifact = await build_candidate_bundle(
            db,
            agent_id=AGENT,
            rego_policy=(
                "package acr\n"
                "deny contains reason if {\n"
                '    input.action.tool_name == "send_email"\n'
                '    reason := "send_email disabled by tightened policy"\n'
                "}"
            ),
        )
        start, end = _window()
        record = await run_simulation(
            db,
            actor="test",
            window_start=start,
            window_end=end,
            bundle_bytes=artifact.bytes_data,
            bundle_label="tightened",
        )
        assert len(record.report["samples"]) == 1
        blob = json.dumps(record.report)
        assert CANARY not in blob
        assert REDACTED_MARKER in blob
        assert CANARY not in render_markdown_summary(record.report)


# ── CLI ───────────────────────────────────────────────────────────────────────


class TestSimulationCLI:
    def test_simulate_help(self) -> None:
        result = subprocess.run(
            ["acr", "simulate", "--help"], capture_output=True, text=True, check=False
        )
        assert result.returncode == 0
        assert "--release-id" in result.stdout

    def test_purge_help(self) -> None:
        result = subprocess.run(
            ["acr", "purge-evaluation-inputs", "--help"],
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0
