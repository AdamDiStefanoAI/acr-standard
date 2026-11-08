"""Tests for pillar2_policy/engine.py — OPA client with retry logic."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from acr.common.errors import PolicyEngineError
from acr.pillar2_policy.engine import evaluate_policy
from acr.policy_studio.core_bundle import core_identity, operator_identity

# ── Helpers ───────────────────────────────────────────────────────────────────

AGENT = {"agent_id": "test-agent", "allowed_tools": ["tool_x"]}
ACTION = {"tool_name": "tool_x", "parameters": {}}
CONTEXT = {"actions_this_minute": 2, "hourly_spend_usd": 0.5}


def _make_opa_client(status_code: int, json_data: dict):
    """Build a mock httpx.AsyncClient that returns a fixed OPA response."""
    mock_resp = MagicMock()
    mock_resp.status_code = status_code
    if isinstance(json_data.get("result"), dict):
        json_data["result"]["core_identity"] = core_identity()
        json_data["result"]["operator_identity"] = operator_identity()
    mock_resp.json.return_value = json_data
    mock_resp.raise_for_status = MagicMock()
    mock_resp.request = MagicMock()

    mock_client = AsyncMock()
    mock_client.post = AsyncMock(return_value=mock_resp)
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    return mock_client


# ── Tests ─────────────────────────────────────────────────────────────────────


class TestOPADecisions:
    async def test_allow_decision(self):
        client = _make_opa_client(200, {"result": {"allow": True, "deny": []}})
        with patch("acr.pillar2_policy.engine.httpx.AsyncClient", return_value=client):
            result = await evaluate_policy(AGENT, ACTION, CONTEXT)
        assert result.final_decision == "allow"
        assert len(result.decisions) == 1
        assert result.decisions[0].decision == "allow"
        assert result.decisions[0].policy_id == "acr-allow"

    async def test_deny_decision(self):
        client = _make_opa_client(200, {"result": {"allow": False, "deny": ["Forbidden tool"]}})
        with patch("acr.pillar2_policy.engine.httpx.AsyncClient", return_value=client):
            result = await evaluate_policy(AGENT, ACTION, CONTEXT)
        assert result.final_decision == "deny"
        assert "Forbidden tool" in result.reason

    async def test_multiple_deny_reasons_all_recorded(self):
        client = _make_opa_client(
            200,
            {
                "result": {
                    "allow": False,
                    "deny": ["rate limit exceeded", "spend limit exceeded"],
                }
            },
        )
        with patch("acr.pillar2_policy.engine.httpx.AsyncClient", return_value=client):
            result = await evaluate_policy(AGENT, ACTION, CONTEXT)
        assert result.final_decision == "deny"
        assert len(result.decisions) == 2
        assert "rate limit exceeded" in result.reason

    async def test_escalate_decision(self):
        client = _make_opa_client(
            200,
            {
                "result": {
                    "allow": False,
                    "deny": [],
                    "escalate": True,
                    "escalate_queue": "finance-approvals",
                    "escalate_sla_minutes": 120,
                }
            },
        )
        with patch("acr.pillar2_policy.engine.httpx.AsyncClient", return_value=client):
            result = await evaluate_policy(AGENT, ACTION, CONTEXT)
        assert result.final_decision == "escalate"
        assert result.approval_queue == "finance-approvals"
        assert result.sla_minutes == 120

    async def test_default_deny_when_result_empty(self):
        """OPA returns {} result → deny-by-default."""
        client = _make_opa_client(200, {"result": {}})
        with patch("acr.pillar2_policy.engine.httpx.AsyncClient", return_value=client):
            result = await evaluate_policy(AGENT, ACTION, CONTEXT)
        assert result.final_decision == "deny"
        assert result.decisions[0].policy_id == "acr-default-deny"

    async def test_null_result_treated_as_empty(self):
        """OPA returns result=null → deny-by-default."""
        client = _make_opa_client(200, {"result": None})
        with (
            patch("acr.pillar2_policy.engine.httpx.AsyncClient", return_value=client),
            pytest.raises(PolicyEngineError, match="managed core"),
        ):
            await evaluate_policy(AGENT, ACTION, CONTEXT)


class TestOPAContextDefaults:
    async def test_missing_context_fields_get_safe_defaults(self):
        """Empty context → safe 0/0.0 defaults injected before OPA call."""
        captured: dict = {}

        async def capture_post(path, json=None, **kwargs):
            nonlocal captured
            captured = json or {}
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
            return mock_resp

        mock_client = AsyncMock()
        mock_client.post = capture_post
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("acr.pillar2_policy.engine.httpx.AsyncClient", return_value=mock_client):
            await evaluate_policy(AGENT, ACTION, {})

        ctx = captured["input"]["context"]
        assert ctx["actions_this_minute"] == 0
        assert ctx["hourly_spend_usd"] == 0.0

    async def test_caller_context_overrides_defaults(self):
        """Caller-supplied values override the safe defaults."""
        captured: dict = {}

        async def capture_post(path, json=None, **kwargs):
            nonlocal captured
            captured = json or {}
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
            return mock_resp

        mock_client = AsyncMock()
        mock_client.post = capture_post
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("acr.pillar2_policy.engine.httpx.AsyncClient", return_value=mock_client):
            await evaluate_policy(
                AGENT, ACTION, {"actions_this_minute": 7, "hourly_spend_usd": 2.5}
            )

        ctx = captured["input"]["context"]
        assert ctx["actions_this_minute"] == 7
        assert ctx["hourly_spend_usd"] == 2.5


class TestOPARetryLogic:
    async def test_503_exhausts_all_retries_raises_policy_engine_error(self):
        """OPA returns 503 on every attempt → PolicyEngineError (fail-secure)."""
        mock_resp = MagicMock()
        mock_resp.status_code = 503
        mock_resp.json.return_value = {}
        mock_resp.raise_for_status = MagicMock()
        mock_resp.request = MagicMock()

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with (
            patch("acr.pillar2_policy.engine.httpx.AsyncClient", return_value=mock_client),
            patch("acr.pillar2_policy.engine.asyncio.sleep"),  # skip actual delays
            pytest.raises(PolicyEngineError),
        ):
            await evaluate_policy(AGENT, ACTION, CONTEXT)

        # Should have been called _MAX_RETRIES (3) times
        assert mock_client.post.await_count == 3

    async def test_connection_error_exhausts_retries(self):
        """Network error on every attempt → PolicyEngineError."""
        import httpx as _httpx

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(side_effect=_httpx.ConnectError("connection refused"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with (
            patch("acr.pillar2_policy.engine.httpx.AsyncClient", return_value=mock_client),
            patch("acr.pillar2_policy.engine.asyncio.sleep"),
            pytest.raises(PolicyEngineError),
        ):
            await evaluate_policy(AGENT, ACTION, CONTEXT)

    async def test_success_after_retry(self):
        """First call fails with 503, second succeeds → returns allow."""

        fail_resp = MagicMock()
        fail_resp.status_code = 503
        fail_resp.json.return_value = {}
        fail_resp.raise_for_status = MagicMock()
        fail_resp.request = MagicMock()

        ok_resp = MagicMock()
        ok_resp.status_code = 200
        ok_resp.json.return_value = {
            "result": {
                "allow": True,
                "deny": [],
                "core_identity": core_identity(),
                "operator_identity": operator_identity(),
            }
        }
        ok_resp.raise_for_status = MagicMock()
        ok_resp.request = MagicMock()

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(side_effect=[fail_resp, ok_resp])
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with (
            patch("acr.pillar2_policy.engine.httpx.AsyncClient", return_value=mock_client),
            patch("acr.pillar2_policy.engine.asyncio.sleep"),
        ):
            result = await evaluate_policy(AGENT, ACTION, CONTEXT)

        assert result.final_decision == "allow"
        assert mock_client.post.await_count == 2

    async def test_400_raises_policy_engine_error(self):
        """4xx errors flow through raise_for_status → HTTPStatusError caught by general
        except block → retried until all attempts exhausted → PolicyEngineError."""
        import httpx as _httpx

        mock_resp = MagicMock()
        mock_resp.status_code = 400
        mock_resp.json.return_value = {}
        mock_resp.raise_for_status = MagicMock(
            side_effect=_httpx.HTTPStatusError(
                "bad request", request=MagicMock(), response=MagicMock()
            )
        )
        mock_resp.request = MagicMock()

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with (
            patch("acr.pillar2_policy.engine.httpx.AsyncClient", return_value=mock_client),
            patch("acr.pillar2_policy.engine.asyncio.sleep"),
            pytest.raises(PolicyEngineError),
        ):
            await evaluate_policy(AGENT, ACTION, CONTEXT)

        # 4xx goes through the generic except handler → retried all 3 times
        assert mock_client.post.await_count == 3
