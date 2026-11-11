"""Registration is committed before a caller can request its first token."""

from unittest.mock import AsyncMock, patch

import pytest

from acr.common.operator_auth import OperatorPrincipal
from acr.pillar1_identity.models import AgentRegisterRequest
from acr.pillar1_identity.router import register_agent


async def test_registration_commits_before_return(db):
    original = db.commit
    db.commit = AsyncMock(wraps=original)
    response = await register_agent(
        AgentRegisterRequest(
            agent_id="durable-agent",
            owner="fixture@example.invalid",
            purpose="durability fixture",
            allowed_tools=["read"],
        ),
        db,
        OperatorPrincipal(subject="fixture", roles=frozenset({"agent_admin"})),
    )
    db.commit.assert_awaited_once()
    assert response.agent_id == "durable-agent"


async def test_registration_storage_failure_cannot_return_success(db):
    with (
        patch.object(db, "commit", AsyncMock(side_effect=OSError("fixture storage failure"))),
        pytest.raises(OSError),
    ):
        await register_agent(
            AgentRegisterRequest(
                agent_id="uncommitted-agent",
                owner="fixture@example.invalid",
                purpose="durability fixture",
                allowed_tools=["read"],
            ),
            db,
            OperatorPrincipal(subject="fixture", roles=frozenset({"agent_admin"})),
        )
