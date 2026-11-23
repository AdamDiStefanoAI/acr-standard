"""WS3 auditor surface: time-boxed grants, central read-only enforcement,
decision explorer chain assembly, and the verifiable evidence package."""

from __future__ import annotations

import json
import subprocess
import sys
import zipfile
from collections.abc import AsyncGenerator
from datetime import timedelta
from io import BytesIO
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest_asyncio
from fastapi import Request as FastAPIRequest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from acr.common.time import utcnow
from acr.db.database import get_db
from acr.db.models import (
    ApprovalRequestRecord,
    ContainmentActionRecord,
    DriftMetricRecord,
    EvaluationInputRecord,
    ExecutionReceiptRecord,
    PolicyDecisionRecord,
    PolicyReleaseRecord,
    PolicySimulationRecord,
    TelemetryEventRecord,
)
from acr.gateway.auth import require_agent_token
from acr.main import app
from acr.operator_keys.models import AuditorGrantCreateRequest, OperatorKeyCreateRequest
from acr.operator_keys.service import create_auditor_grant, create_operator_key
from acr.pillar1_identity.models import AgentRegisterRequest
from acr.pillar1_identity.registry import register_agent
from acr.pillar4_observability.input_retention import canonical_payload_hash

AGENT = "auditor-agent"
CANARY = "CANARY-SECRET-VALUE-7f3a9"


# ── Real-auth client (conftest's client overrides the operator principal;
#    grant enforcement can only be tested with the real auth path) ───────────


@pytest_asyncio.fixture(scope="function")
async def real_auth_client(test_engine) -> AsyncGenerator[AsyncClient, None]:
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

    async def _mock_agent_auth(request: FastAPIRequest) -> str:
        body = await request.json()
        return body.get("agent_id", "")

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[require_agent_token] = _mock_agent_auth
    with (
        patch("acr.gateway.router.is_agent_killed", new_callable=AsyncMock, return_value=False),
        patch("acr.gateway.router.get_redis_or_none", return_value=None),
        patch("acr.gateway.router._queue_background_tasks"),
        patch(
            "acr.pillar5_containment.router.list_kill_status",
            new_callable=AsyncMock,
            return_value=[],
        ),
        patch(
            "acr.pillar5_containment.router.get_kill_status",
            new_callable=AsyncMock,
            return_value={"agent_id": AGENT, "is_killed": False},
        ),
    ):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            yield client
    settings.allow_degraded_dependencies = previous_degraded
    app.dependency_overrides.clear()


async def _admin_key(db: AsyncSession) -> str:
    _record, api_key = await create_operator_key(
        db,
        req=OperatorKeyCreateRequest(
            name="Security Admin", subject="sec@example.com", roles=["security_admin"]
        ),
        created_by="test",
    )
    await db.commit()
    return api_key


async def _grant_key(db: AsyncSession, *, lifetime_hours: int = 24) -> str:
    _record, api_key = await create_auditor_grant(
        db,
        req=AuditorGrantCreateRequest(
            name="External Auditor",
            subject="auditor@firm.example",
            lifetime_hours=lifetime_hours,
        ),
        created_by="sec@example.com",
    )
    await db.commit()
    return api_key


def _headers(api_key: str) -> dict[str, str]:
    return {"X-Operator-API-Key": api_key}


async def _register(db: AsyncSession, agent_id: str = AGENT) -> None:
    await register_agent(
        db,
        AgentRegisterRequest(
            agent_id=agent_id,
            owner="ops@example.com",
            purpose="Auditor surface test agent",
            risk_tier="medium",
            allowed_tools=["issue_refund", "query_customer_db"],
        ),
    )
    await db.commit()


# ── Grant issuance ────────────────────────────────────────────────────────────


class TestAuditorGrants:
    async def test_issuance_via_api_is_time_boxed_and_auditor_only(
        self, real_auth_client: AsyncClient, db: AsyncSession
    ) -> None:
        admin = await _admin_key(db)
        resp = await real_auth_client.post(
            "/acr/operator-keys/auditor-grants",
            json={"name": "Q4 Audit", "subject": "auditor@firm.example", "lifetime_hours": 48},
            headers=_headers(admin),
        )
        assert resp.status_code == 201
        payload = resp.json()
        assert payload["roles"] == ["auditor"]
        assert payload["expires_at"] is not None
        assert payload["api_key"].startswith("acr_op_")

    async def test_issuance_requires_expiry_and_respects_cap(
        self, real_auth_client: AsyncClient, db: AsyncSession
    ) -> None:
        admin = await _admin_key(db)
        missing = await real_auth_client.post(
            "/acr/operator-keys/auditor-grants",
            json={"name": "No Expiry", "subject": "a@firm.example"},
            headers=_headers(admin),
        )
        assert missing.status_code == 422
        over_cap = await real_auth_client.post(
            "/acr/operator-keys/auditor-grants",
            json={"name": "Too Long", "subject": "a@firm.example", "lifetime_hours": 24 * 31},
            headers=_headers(admin),
        )
        assert over_cap.status_code == 422

    async def test_issuance_requires_security_admin(
        self, real_auth_client: AsyncClient, db: AsyncSession
    ) -> None:
        grant = await _grant_key(db)
        resp = await real_auth_client.post(
            "/acr/operator-keys/auditor-grants",
            json={"name": "Self Issue", "subject": "a@firm.example", "lifetime_hours": 1},
            headers=_headers(grant),
        )
        assert resp.status_code == 403

    async def test_expired_grant_rejected_everywhere(
        self, real_auth_client: AsyncClient, db: AsyncSession
    ) -> None:
        record, api_key = await create_auditor_grant(
            db,
            req=AuditorGrantCreateRequest(
                name="Short", subject="auditor@firm.example", lifetime_hours=1
            ),
            created_by="sec@example.com",
        )
        await db.commit()
        record.expires_at = utcnow() - timedelta(minutes=1)
        await db.commit()
        resp = await real_auth_client.get("/acr/decisions", headers=_headers(api_key))
        assert resp.status_code == 401

    async def test_revoked_grant_rejected(
        self, real_auth_client: AsyncClient, db: AsyncSession
    ) -> None:
        admin = await _admin_key(db)
        issued = await real_auth_client.post(
            "/acr/operator-keys/auditor-grants",
            json={"name": "Revoke Me", "subject": "a@firm.example", "lifetime_hours": 4},
            headers=_headers(admin),
        )
        grant_key = issued.json()["api_key"]
        key_id = issued.json()["key_id"]
        ok = await real_auth_client.get("/acr/decisions", headers=_headers(grant_key))
        assert ok.status_code == 200
        revoked = await real_auth_client.post(
            f"/acr/operator-keys/{key_id}/revoke", headers=_headers(admin)
        )
        assert revoked.status_code == 200
        resp = await real_auth_client.get("/acr/decisions", headers=_headers(grant_key))
        assert resp.status_code == 401


# ── Central read-only + scope enforcement ─────────────────────────────────────


class TestAuditorScopeEnforcement:
    async def test_auditor_can_read_in_scope_surfaces(
        self, real_auth_client: AsyncClient, db: AsyncSession
    ) -> None:
        await _register(db)
        grant = await _grant_key(db)
        headers = _headers(grant)
        for path in (
            "/acr/decisions",
            "/acr/agents",
            f"/acr/agents/{AGENT}",
            f"/acr/agents/{AGENT}/observe-report",
            "/acr/policy-drafts/releases/history",
            "/acr/approvals",
            "/acr/containment/status",
            "/acr/events",
            "/acr/auth/session",
        ):
            resp = await real_auth_client.get(path, headers=headers)
            assert resp.status_code == 200, f"{path} -> {resp.status_code}: {resp.text}"

    async def test_auditor_rejected_by_write_routes(
        self, real_auth_client: AsyncClient, db: AsyncSession
    ) -> None:
        await _register(db)
        grant = await _grant_key(db)
        headers = _headers(grant)
        writes = [
            ("POST", "/acr/evaluate", {"agent_id": AGENT, "action": {"tool_name": "issue_refund"}}),
            (
                "POST",
                "/acr/agents",
                {"agent_id": "new-agent", "owner": "o@example.com", "purpose": "p"},
            ),
            ("PUT", f"/acr/agents/{AGENT}", {"owner": "other@example.com"}),
            ("DELETE", f"/acr/agents/{AGENT}", None),
            ("POST", f"/acr/agents/{AGENT}/lifecycle", {"target_state": "deprecated"}),
            ("POST", f"/acr/agents/{AGENT}/enforcement-mode", {"target_mode": "observe"}),
            ("POST", f"/acr/agents/{AGENT}/token", None),
            ("POST", f"/acr/agents/{AGENT}/heartbeat", {"health_status": "healthy"}),
            (
                "POST",
                "/acr/policy-drafts",
                {
                    "name": "d",
                    "agent_id": AGENT,
                    "template": "t",
                    "manifest": {},
                    "rego_policy": "package acr",
                    "wizard_inputs": {},
                },
            ),
            ("POST", "/acr/policy-drafts/some-draft/publish", {"notes": None}),
            ("POST", "/acr/policy-drafts/releases/some-release/activate", None),
            ("POST", "/acr/approvals/some-request/approve", {"reason": "ok"}),
            ("POST", "/acr/approvals/some-request/deny", {"reason": "no"}),
            ("POST", "/acr/approvals/some-request/execute", None),
            (
                "POST",
                "/acr/operator-keys",
                {"name": "k", "subject": "s@example.com", "roles": ["security_admin"]},
            ),
            ("POST", "/acr/operator-keys/some-key/revoke", None),
            ("POST", "/acr/operator-keys/some-key/rotate", None),
            ("POST", "/acr/containment/kill", {"agent_id": AGENT, "reason": "test"}),
            ("POST", "/acr/containment/restore", {"agent_id": AGENT}),
            (
                "POST",
                "/acr/policy-simulations",
                {
                    "release_id": "rel-1",
                    "window_start": "2026-11-01T00:00:00Z",
                    "window_end": "2026-11-02T00:00:00Z",
                },
            ),
            (
                "POST",
                "/acr/evidence-packages",
                {
                    "window_start": "2026-11-01T00:00:00Z",
                    "window_end": "2026-11-02T00:00:00Z",
                },
            ),
            ("POST", f"/acr/drift/{AGENT}/baseline/reset", None),
        ]
        for method, path, body in writes:
            resp = await real_auth_client.request(method, path, json=body, headers=headers)
            assert resp.status_code == 403, f"{method} {path} -> {resp.status_code}: {resp.text}"

    async def test_auditor_rejected_by_out_of_scope_reads(
        self, real_auth_client: AsyncClient, db: AsyncSession
    ) -> None:
        await _register(db)
        grant = await _grant_key(db)
        headers = _headers(grant)
        for path in (
            "/acr/operator-keys",
            "/acr/policy-drafts",
            "/acr/policy-drafts/some-draft",
            "/acr/policy-drafts/some-draft/bundle",
            f"/acr/drift/{AGENT}",
            f"/acr/drift/{AGENT}/baseline",
        ):
            resp = await real_auth_client.get(path, headers=headers)
            assert resp.status_code == 403, f"{path} -> {resp.status_code}: {resp.text}"


# ── Explorer ──────────────────────────────────────────────────────────────────


async def _seed_chain(db: AsyncSession, *, full: bool) -> str:
    """Seed one action. full=True links approval, receipt, retained input,
    and telemetry; full=False leaves a bare decision."""
    now = utcnow()
    correlation_id = "corr-full" if full else "corr-bare"
    decision = PolicyDecisionRecord(
        correlation_id=correlation_id,
        agent_id=AGENT,
        policy_id="acr-escalate-0",
        decision="escalate" if full else "allow",
        enforcement_mode="enforce",
        reason="Approval required" if full else "Allowed",
        tool_name="issue_refund",
        latency_ms=3,
        sequence=7 if full else 8,
        created_at=now,
    )
    db.add(decision)
    if full:
        payload = {
            "agent": {"agent_id": AGENT, "purpose": "Handle support", "version": "1.0.0"},
            "action": {"tool_name": "issue_refund", "parameters": {"amount": 42}},
            "context": {},
        }
        db.add(
            EvaluationInputRecord(
                correlation_id=correlation_id,
                agent_id=AGENT,
                payload=payload,
                payload_sha256=canonical_payload_hash(payload),
                recorded_decision="escalate",
                enforcement_mode="enforce",
                state="retained",
                retained_at=now,
                expires_at=now + timedelta(days=30),
            )
        )
        db.add(
            ApprovalRequestRecord(
                request_id="apr-full",
                correlation_id=correlation_id,
                agent_id=AGENT,
                tool_name="issue_refund",
                parameters={"amount": 42},
                risk_tier="high",
                approval_queue="default",
                status="approved",
                decision="approved",
                decided_by="approver@example.com",
                decision_reason="verified",
                decided_at=now,
                created_at=now,
                authorization_snapshot={
                    "manifest_hash": "mh-1",
                    "policy_identity": {"bundle_sha256": "bundle-abc"},
                },
            )
        )
        db.add(
            ExecutionReceiptRecord(
                approval_request_id="apr-full",
                payload_hash="a" * 64,
                authorization_snapshot={},
                state="succeeded",
                result={"status": "ok"},
                created_at=now,
                completed_at=now,
            )
        )
        db.add(
            TelemetryEventRecord(
                event_id="evt-full",
                correlation_id=correlation_id,
                event_type="policy_decision",
                agent_id=AGENT,
                payload={"event_type": "policy_decision", "output": {"decision": "escalate"}},
                created_at=now,
            )
        )
    await db.commit()
    await db.refresh(decision)
    return str(decision.id)


class TestDecisionExplorer:
    async def test_full_chain_is_complete(
        self, async_client: AsyncClient, db: AsyncSession
    ) -> None:
        await _register(db)
        decision_id = await _seed_chain(db, full=True)
        resp = await async_client.get("/acr/decisions/chain/corr-full")
        assert resp.status_code == 200
        chain = resp.json()
        assert chain["manifest_snapshot"]["agent_id"] == AGENT
        assert chain["manifest_link"]["status"] == "present"
        assert chain["policy_ids"] == ["acr-escalate-0"]
        assert chain["policy_bundle_identifier"] == {"bundle_sha256": "bundle-abc"}
        assert chain["decisions"][0]["sequence"] == 7
        assert chain["approval"]["request_id"] == "apr-full"
        assert chain["approval"]["decided_by"] == "approver@example.com"
        assert chain["execution_receipt"]["state"] == "succeeded"
        assert len(chain["telemetry_events"]) == 1
        assert chain["missing_links"] == []

        by_id = await async_client.get(f"/acr/decisions/chain/{decision_id}")
        assert by_id.status_code == 200
        assert by_id.json()["correlation_id"] == "corr-full"

    async def test_bare_chain_states_missing_links(
        self, async_client: AsyncClient, db: AsyncSession
    ) -> None:
        await _register(db)
        await _seed_chain(db, full=False)
        resp = await async_client.get("/acr/decisions/chain/corr-bare")
        assert resp.status_code == 200
        chain = resp.json()
        assert chain["manifest_snapshot"] is None
        assert chain["manifest_link"]["status"] == "absent"
        assert chain["approval"] is None
        assert chain["approval_link"]["status"] == "absent"
        assert chain["execution_link"]["status"] == "absent"
        assert chain["telemetry_link"]["status"] == "absent"
        assert set(chain["missing_links"]) == {
            "manifest_snapshot",
            "policy_bundle_identifier",
            "approval",
            "execution_receipt",
            "telemetry_events",
        }

    async def test_filters_reconcile_with_database(
        self, async_client: AsyncClient, db: AsyncSession
    ) -> None:
        await _register(db)
        now = utcnow()
        rows = [
            ("deny", "enforce", "issue_refund", "Destructive action blocked", 1),
            ("deny", "observe", "issue_refund", "Destructive action blocked", 2),
            ("allow", "enforce", "query_customer_db", "Allowed", 3),
            ("deny", "enforce", "delete_customer", "Forbidden tool", 4),
        ]
        for index, (decision, mode, tool, reason, seq) in enumerate(rows):
            db.add(
                PolicyDecisionRecord(
                    correlation_id=f"corr-filter-{index}",
                    agent_id=AGENT,
                    policy_id="acr-test",
                    decision=decision,
                    enforcement_mode=mode,
                    reason=reason,
                    tool_name=tool,
                    sequence=seq,
                    created_at=now - timedelta(hours=index),
                )
            )
        await db.commit()

        async def _total(params: str) -> int:
            resp = await async_client.get(f"/acr/decisions?{params}")
            assert resp.status_code == 200
            return resp.json()["total"]

        assert await _total("decision=deny") == 3
        assert await _total("decision=deny&enforcement_mode=observe") == 1
        assert await _total("tool_name=issue_refund") == 2
        assert await _total("reason_contains=Destructive") == 2
        assert await _total(f"agent_id={AGENT}&decision=allow") == 1
        assert await _total("correlation_id=corr-filter-3") == 1

        raw = (
            await db.execute(
                select(func.count())
                .select_from(PolicyDecisionRecord)
                .where(PolicyDecisionRecord.decision == "deny")
            )
        ).scalar_one()
        assert await _total("decision=deny") == raw

        page = await async_client.get("/acr/decisions?limit=2&offset=2")
        assert page.json()["total"] == 4
        assert len(page.json()["items"]) == 2
        newest_first = await async_client.get("/acr/decisions?limit=1")
        assert newest_first.json()["items"][0]["correlation_id"] == "corr-filter-0"


# ── Evidence package ──────────────────────────────────────────────────────────

WINDOW_START = None  # set in _seed_package


async def _seed_package(db: AsyncSession) -> tuple:
    await _register(db)
    now = utcnow()
    start, end = now - timedelta(days=1), now + timedelta(hours=1)
    payload = {
        "agent": {"agent_id": AGENT},
        "action": {"tool_name": "issue_refund", "parameters": {"secret_note": CANARY}},
        "context": {},
    }
    db.add_all(
        [
            PolicyDecisionRecord(
                correlation_id="corr-pkg-1",
                agent_id=AGENT,
                policy_id="acr-deny-0",
                decision="deny",
                enforcement_mode="enforce",
                reason="Blocked",
                tool_name="issue_refund",
                sequence=1,
                created_at=now,
            ),
            PolicyDecisionRecord(
                correlation_id="corr-pkg-2",
                agent_id=AGENT,
                policy_id="acr-allow-0",
                decision="allow",
                enforcement_mode="observe",
                reason="Allowed",
                tool_name="query_customer_db",
                sequence=2,
                created_at=now,
            ),
            ApprovalRequestRecord(
                request_id="apr-pkg",
                correlation_id="corr-pkg-1",
                agent_id=AGENT,
                tool_name="issue_refund",
                parameters={"secret_note": CANARY},
                risk_tier="high",
                status="approved",
                decision="approved",
                decided_by="approver@example.com",
                created_at=now,
            ),
            ContainmentActionRecord(
                agent_id=AGENT,
                action_type="restrict",
                tier=2,
                reason="drift",
                operator_id="sec@example.com",
                correlation_id="corr-pkg-1",
                created_at=now,
            ),
            EvaluationInputRecord(
                correlation_id="corr-pkg-1",
                agent_id=AGENT,
                payload=payload,
                payload_sha256=canonical_payload_hash(payload),
                recorded_decision="deny",
                enforcement_mode="enforce",
                state="retained",
                retained_at=now,
                expires_at=now + timedelta(days=30),
            ),
            PolicyReleaseRecord(
                release_id="rel-pkg",
                draft_id="draft-pkg",
                agent_id=AGENT,
                version=1,
                name="Pkg Release",
                template="customer_support",
                manifest={"agent_id": AGENT},
                rego_policy="package acr",
                status="published",
                activation_status="active",
                artifact_sha256="b" * 64,
                created_at=now,
            ),
            PolicySimulationRecord(
                run_id="sim-pkg",
                actor="sec@example.com",
                bundle_label="rel-pkg",
                bundle_sha256="c" * 64,
                window_start=start,
                window_end=end,
                decisions_in_window=2,
                inputs_available=1,
                inputs_missing=1,
                report={"run_id": "sim-pkg"},
                result_hash="d" * 64,
                created_at=now,
            ),
            DriftMetricRecord(
                agent_id=AGENT,
                correlation_id="corr-pkg-1",
                tool_name="issue_refund",
                action_type="issue_refund",
                policy_denied=True,
                latency_ms=3,
                created_at=now,
            ),
        ]
    )
    await db.commit()
    return start, end


def _extract(zip_bytes: bytes, dest: Path) -> Path:
    dest.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(BytesIO(zip_bytes)) as archive:
        archive.extractall(dest)
    return dest


def _verify(package_dir: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(package_dir / "verify_package.py"), str(package_dir)],
        capture_output=True,
        text=True,
        timeout=60,
    )


class TestEvidencePackage:
    async def test_package_verifies_clean_and_hides_payloads(
        self, db: AsyncSession, tmp_path: Path
    ) -> None:
        from acr.pillar4_observability.evidence_package import generate_evidence_package

        start, end = await _seed_package(db)
        artifact = await generate_evidence_package(
            db, actor="sec@example.com", window_start=start, window_end=end
        )
        package_dir = _extract(artifact.bytes_data, tmp_path / "pkg")
        result = _verify(package_dir)
        assert result.returncode == 0, result.stderr
        assert "verification passed" in result.stdout

        combined = b"".join(path.read_bytes() for path in package_dir.rglob("*") if path.is_file())
        assert CANARY.encode() not in combined
        manifest = json.loads((package_dir / "MANIFEST.json").read_text())
        assert manifest["generated_by"] == "sec@example.com"
        assert manifest["file_count"] == len(manifest["entries"])
        assert (package_dir / "control-mapping.md").is_file()
        inputs = json.loads((package_dir / "evaluation-inputs.json").read_text())
        assert inputs[0]["payload_included"] is False
        assert "payload" not in inputs[0]

    async def test_package_tamper_delete_and_reorder_fail(
        self, db: AsyncSession, tmp_path: Path
    ) -> None:
        from acr.pillar4_observability.evidence_package import generate_evidence_package

        start, end = await _seed_package(db)
        artifact = await generate_evidence_package(
            db, actor="sec@example.com", window_start=start, window_end=end
        )

        tampered = _extract(artifact.bytes_data, tmp_path / "tampered")
        decisions = tampered / "decisions.jsonl"
        decisions.write_bytes(decisions.read_bytes() + b'{"tampered": true}\n')
        result = _verify(tampered)
        assert result.returncode != 0
        assert "sha256 mismatch" in result.stderr

        deleted = _extract(artifact.bytes_data, tmp_path / "deleted")
        (deleted / "approvals.json").unlink()
        result = _verify(deleted)
        assert result.returncode != 0
        assert "missing" in result.stderr

        reordered = _extract(artifact.bytes_data, tmp_path / "reordered")
        manifest_path = reordered / "MANIFEST.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["entries"] = list(reversed(manifest["entries"]))
        manifest_path.write_text(json.dumps(manifest, indent=2))
        result = _verify(reordered)
        assert result.returncode != 0
        assert "hash chain" in result.stderr

    async def test_package_via_api(self, async_client: AsyncClient, db: AsyncSession) -> None:
        start, end = await _seed_package(db)
        resp = await async_client.post(
            "/acr/evidence-packages",
            json={"window_start": start.isoformat(), "window_end": end.isoformat()},
        )
        assert resp.status_code == 200
        assert resp.headers["content-type"] == "application/zip"
        assert len(resp.headers["x-evidence-chain-head"]) == 64
        with zipfile.ZipFile(BytesIO(resp.content)) as archive:
            names = set(archive.namelist())
        assert {"MANIFEST.json", "decisions.jsonl", "verify_package.py"} <= names

    async def test_package_directory_output_via_generator(
        self, db: AsyncSession, tmp_path: Path
    ) -> None:
        from acr.pillar4_observability.evidence_package import write_evidence_package

        start, end = await _seed_package(db)
        out = tmp_path / "pkgdir"
        result = await write_evidence_package(
            db, actor="cli", window_start=start, window_end=end, output=out
        )
        assert result["file_count"] > 5
        verify = _verify(out)
        assert verify.returncode == 0, verify.stderr


def test_packaged_control_mapping_matches_docs_source():
    """The packaged copy under src/acr/_compliance must stay byte-identical
    to docs/compliance/control-mapping.md (the human-edited source of truth);
    the Docker build only ships src/, so the package carries its own copy."""
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    doc = (root / "docs" / "compliance" / "control-mapping.md").read_bytes()
    packaged = (root / "src" / "acr" / "_compliance" / "control-mapping.md").read_bytes()
    assert doc == packaged
