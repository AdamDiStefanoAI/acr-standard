from __future__ import annotations

import hashlib
import io
import json
import tarfile

from httpx import AsyncClient

from acr.config import settings
from acr.policy_studio.core_bundle import core_identity


class TestPolicyDraftAPI:
    async def test_create_list_get_and_update_policy_draft(self, async_client: AsyncClient) -> None:
        create_resp = await async_client.post(
            "/acr/policy-drafts",
            json={
                "name": "Customer support starter",
                "agent_id": "support-bot-01",
                "template": "customer_support",
                "manifest": {
                    "agent_id": "support-bot-01",
                    "owner": "support@example.com",
                    "purpose": "Handle support cases",
                    "risk_tier": "medium",
                },
                "rego_policy": "package acr\nallow if { true }",
                "wizard_inputs": {"template": "customer_support"},
            },
        )
        assert create_resp.status_code == 201
        created = create_resp.json()
        assert created["draft_id"].startswith("pdr-")

        list_resp = await async_client.get("/acr/policy-drafts")
        assert list_resp.status_code == 200
        assert any(item["draft_id"] == created["draft_id"] for item in list_resp.json())

        get_resp = await async_client.get(f"/acr/policy-drafts/{created['draft_id']}")
        assert get_resp.status_code == 200
        assert get_resp.json()["name"] == "Customer support starter"

        update_resp = await async_client.put(
            f"/acr/policy-drafts/{created['draft_id']}",
            json={
                "name": "Customer support starter v2",
                "agent_id": "support-bot-01",
                "template": "customer_support",
                "manifest": {
                    "agent_id": "support-bot-01",
                    "owner": "support@example.com",
                    "purpose": "Handle support cases",
                    "risk_tier": "high",
                },
                "rego_policy": 'package acr\ndeny contains reason if { true; reason := "blocked" }',
                "wizard_inputs": {"template": "customer_support", "risk_tier": "high"},
            },
        )
        assert update_resp.status_code == 200
        assert update_resp.json()["name"] == "Customer support starter v2"
        assert update_resp.json()["manifest"]["risk_tier"] == "high"

    async def test_simulate_and_export_bundle(self, async_client: AsyncClient) -> None:
        create_resp = await async_client.post(
            "/acr/policy-drafts",
            json={
                "name": "Refund policy draft",
                "agent_id": "refund-bot-01",
                "template": "customer_support",
                "manifest": {
                    "agent_id": "refund-bot-01",
                    "owner": "support@example.com",
                    "purpose": "Handle refunds",
                    "risk_tier": "medium",
                    "allowed_tools": ["issue_refund", "send_email"],
                    "forbidden_tools": ["delete_customer"],
                    "boundaries": {
                        "max_actions_per_minute": 30,
                        "max_cost_per_hour_usd": 5.0,
                    },
                },
                "rego_policy": 'package acr\nescalate if { input.action.tool_name == "issue_refund" }',
                "wizard_inputs": {
                    "template": "customer_support",
                    "escalate_tool": "issue_refund",
                    "escalate_over_amount": "100",
                    "approval_queue": "finance-approvals",
                    "pii_fields": "body",
                },
            },
        )
        draft_id = create_resp.json()["draft_id"]

        simulate_resp = await async_client.post(
            f"/acr/policy-drafts/{draft_id}/simulate",
            json={
                "action": {"tool_name": "issue_refund", "parameters": {"amount": 250}},
                "context": {"actions_this_minute": 2, "hourly_spend_usd": 1.0},
            },
        )
        assert simulate_resp.status_code == 200
        assert simulate_resp.json()["final_decision"] == "escalate"
        assert simulate_resp.json()["approval_queue"] == "finance-approvals"

        bundle_resp = await async_client.get(f"/acr/policy-drafts/{draft_id}/bundle")
        assert bundle_resp.status_code == 200
        bundle = bundle_resp.json()
        assert bundle["policy_filename"] == "refund-bot-01.rego"
        assert bundle["manifest_filename"] == "refund-bot-01.manifest.json"

    async def test_validate_publish_and_rollback_release(self, async_client: AsyncClient) -> None:
        create_resp = await async_client.post(
            "/acr/policy-drafts",
            json={
                "name": "Publishable draft",
                "agent_id": "publish-bot-01",
                "template": "customer_support",
                "manifest": {
                    "agent_id": "publish-bot-01",
                    "owner": "ops@example.com",
                    "purpose": "Handle support work",
                    "risk_tier": "medium",
                    "allowed_tools": ["query_customer_db"],
                    "forbidden_tools": ["delete_customer"],
                    "boundaries": {
                        "max_actions_per_minute": 30,
                        "max_cost_per_hour_usd": 5.0,
                    },
                },
                "rego_policy": "package acr\nallow if { true }",
                "wizard_inputs": {"template": "customer_support"},
            },
        )
        draft_id = create_resp.json()["draft_id"]

        validate_resp = await async_client.get(f"/acr/policy-drafts/{draft_id}/validate")
        assert validate_resp.status_code == 200
        assert validate_resp.json()["valid"] is True

        publish_resp = await async_client.post(
            f"/acr/policy-drafts/{draft_id}/publish",
            json={"notes": "First production publish"},
        )
        assert publish_resp.status_code == 201
        release = publish_resp.json()
        assert release["version"] == 1
        assert release["status"] == "published"
        assert release["activation_status"] == "inactive"
        assert release["publish_backend"] == "local"
        assert release["artifact_uri"]
        assert release["artifact_sha256"]

        activate_resp = await async_client.post(
            f"/acr/policy-drafts/releases/{release['release_id']}/activate",
        )
        assert activate_resp.status_code == 200
        activated = activate_resp.json()
        assert activated["activation_status"] == "active"
        assert activated["active_bundle_uri"]

        history_resp = await async_client.get("/acr/policy-drafts/releases/history")
        assert history_resp.status_code == 200
        assert any(item["release_id"] == release["release_id"] for item in history_resp.json())

        rollback_resp = await async_client.post(
            f"/acr/policy-drafts/releases/{release['release_id']}/rollback",
            json={"notes": "Rollback test"},
        )
        assert rollback_resp.status_code == 200
        rollback_release = rollback_resp.json()
        assert rollback_release["version"] == 2
        assert rollback_release["activation_status"] == "inactive"
        assert rollback_release["rollback_from_release_id"] == release["release_id"]

    async def test_publish_release_to_s3_backend(
        self,
        async_client: AsyncClient,
        monkeypatch,
    ) -> None:
        uploads: list[dict[str, object]] = []

        class FakeS3Client:
            def put_object(self, **kwargs) -> None:
                uploads.append(kwargs)

        monkeypatch.setattr(settings, "policy_bundle_backend", "s3")
        monkeypatch.setattr(settings, "policy_bundle_s3_bucket", "acr-policy-bundles")
        monkeypatch.setattr(settings, "policy_bundle_s3_prefix", "prod/releases")
        monkeypatch.setattr(settings, "policy_bundle_s3_region", "us-east-1")
        monkeypatch.setattr(settings, "policy_bundle_s3_endpoint_url", "")
        monkeypatch.setattr(settings, "policy_bundle_public_base_url", "")
        monkeypatch.setattr(
            "acr.policy_studio.publisher._s3_client",
            lambda: FakeS3Client(),
        )

        create_resp = await async_client.post(
            "/acr/policy-drafts",
            json={
                "name": "S3 publish draft",
                "agent_id": "s3-publish-bot-01",
                "template": "customer_support",
                "manifest": {
                    "agent_id": "s3-publish-bot-01",
                    "owner": "ops@example.com",
                    "purpose": "Publish bundles to object storage",
                    "risk_tier": "medium",
                    "allowed_tools": ["query_customer_db"],
                    "forbidden_tools": ["delete_customer"],
                    "boundaries": {
                        "max_actions_per_minute": 30,
                        "max_cost_per_hour_usd": 5.0,
                    },
                },
                "rego_policy": "package acr\nallow if { true }",
                "wizard_inputs": {"template": "customer_support"},
            },
        )
        draft_id = create_resp.json()["draft_id"]

        publish_resp = await async_client.post(
            f"/acr/policy-drafts/{draft_id}/publish",
            json={"notes": "Publish to S3"},
        )
        assert publish_resp.status_code == 201
        release = publish_resp.json()
        assert release["publish_backend"] == "s3"
        assert release["artifact_uri"].startswith("s3://acr-policy-bundles/prod/releases/")
        assert release["artifact_sha256"]

        assert len(uploads) == 1
        upload = uploads[0]
        assert upload["Bucket"] == "acr-policy-bundles"
        assert str(upload["Key"]).startswith("prod/releases/s3-publish-bot-01/v1/")
        assert upload["ContentType"] == "application/gzip"
        assert upload["Metadata"]["sha256"] == release["artifact_sha256"]

        activate_resp = await async_client.post(
            f"/acr/policy-drafts/releases/{release['release_id']}/activate",
        )
        assert activate_resp.status_code == 200
        activated = activate_resp.json()
        assert activated["activation_status"] == "active"
        assert (
            activated["active_bundle_uri"]
            == "s3://acr-policy-bundles/prod/releases/s3-publish-bot-01/active/current.tar.gz"
        )

        assert len(uploads) == 2
        active_upload = uploads[1]
        assert active_upload["Bucket"] == "acr-policy-bundles"
        assert active_upload["Key"] == "prod/releases/s3-publish-bot-01/active/current.tar.gz"
        assert active_upload["Metadata"]["sha256"] == release["artifact_sha256"]

    async def test_active_runtime_bundle_and_discovery_document(
        self,
        async_client: AsyncClient,
    ) -> None:
        create_resp = await async_client.post(
            "/acr/policy-drafts",
            json={
                "name": "Bundle runtime draft",
                "agent_id": "runtime-bot-01",
                "template": "customer_support",
                "manifest": {
                    "agent_id": "runtime-bot-01",
                    "owner": "ops@example.com",
                    "purpose": "Serve active runtime bundle",
                    "risk_tier": "medium",
                    "allowed_tools": ["query_customer_db"],
                    "forbidden_tools": ["delete_customer"],
                    "boundaries": {
                        "max_actions_per_minute": 30,
                        "max_cost_per_hour_usd": 5.0,
                    },
                },
                "rego_policy": 'package acr\nescalate if {\n    input.action.tool_name == "issue_refund"\n}',
                "wizard_inputs": {"template": "customer_support"},
            },
        )
        draft_id = create_resp.json()["draft_id"]

        publish_resp = await async_client.post(
            f"/acr/policy-drafts/{draft_id}/publish",
            json={"notes": "Runtime bundle publish"},
        )
        release = publish_resp.json()

        activate_resp = await async_client.post(
            f"/acr/policy-drafts/releases/{release['release_id']}/activate",
        )
        assert activate_resp.status_code == 200

        bundle_resp = await async_client.get("/acr/policy-bundles/active.tar.gz")
        assert bundle_resp.status_code == 200
        assert bundle_resp.headers["x-policy-bundle-sha256"]

        tar_bytes = io.BytesIO(bundle_resp.content)
        with tarfile.open(fileobj=tar_bytes, mode="r:gz") as bundle:
            names = set(bundle.getnames())
            assert "bundle/common.rego" in names
            assert "bundle/content_safety.rego" in names
            assert (
                f"bundle/agents/modules/{hashlib.sha256(b'runtime-bot-01').hexdigest()}.rego"
                in names
            )
            metadata = json.loads(bundle.extractfile("bundle/metadata.json").read())
            assert metadata["active_agents"] == ["runtime-bot-01"]
            scoped_policy = (
                bundle.extractfile(
                    f"bundle/agents/bridges/{hashlib.sha256(b'runtime-bot-01').hexdigest()}.rego"
                )
                .read()
                .decode()
            )
            assert 'input.agent.agent_id == "runtime-bot-01"' in scoped_policy

        discovery_resp = await async_client.get("/acr/policy-bundles/discovery.json")
        assert discovery_resp.status_code == 200
        discovery = discovery_resp.json()
        assert (
            discovery["bundles"]["acr_active_runtime"]["resource"]
            == f"/acr/policy-bundles/{core_identity()['core_id']}/active.tar.gz"
        )
