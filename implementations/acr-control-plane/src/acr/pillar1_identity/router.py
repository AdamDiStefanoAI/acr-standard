"""Pillar 1: Agent registry API endpoints."""

from __future__ import annotations

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from acr.common.operator_auth import OperatorPrincipal, require_operator_roles
from acr.common.redis_client import get_redis_or_none
from acr.db.database import get_db
from acr.pillar1_identity import registry
from acr.pillar1_identity.models import (
    AgentLineageNode,
    AgentLineageResponse,
    AgentRegisterRequest,
    AgentResponse,
    AgentUpdateRequest,
    HeartbeatRequest,
    LifecycleState,
    LifecycleTransitionRequest,
    TokenResponse,
)
from acr.pillar1_identity.validator import issue_token, validate_agent_identity

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/acr/agents", tags=["Identity"])

# Token issuance rate limit: 10 requests per agent_id per hour.
# Prevents an attacker with a valid agent_id from minting unlimited tokens.
_TOKEN_RATE_LIMIT = 10
_TOKEN_RATE_WINDOW_SECONDS = 3600  # 1 hour
_TOKEN_RATE_KEY_PREFIX = "acr:token:rate:"


async def _check_token_rate_limit(agent_id: str) -> None:
    """
    Increment the hourly token counter for this agent.
    Raises HTTP 429 if the limit is exceeded.
    Silently passes if Redis is unavailable (graceful degradation).
    """
    redis = get_redis_or_none()
    if redis is None:
        return  # degrade gracefully — never block issuance due to missing cache

    key = f"{_TOKEN_RATE_KEY_PREFIX}{agent_id}"
    try:
        count = await redis.incr(key)
        if count == 1:
            # First request in this window — set the TTL
            await redis.expire(key, _TOKEN_RATE_WINDOW_SECONDS)
        if count > _TOKEN_RATE_LIMIT:
            logger.warning("token_rate_limit_exceeded", agent_id=agent_id, count=count)
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=(
                    f"Token issuance rate limit exceeded "
                    f"({_TOKEN_RATE_LIMIT} per hour). Try again later."
                ),
            )
    except HTTPException:
        raise
    except Exception as exc:
        # Redis error — log and allow; never block issuance on cache failure
        logger.warning("token_rate_limit_redis_error", agent_id=agent_id, error=str(exc))


def _to_lineage_node(record) -> AgentLineageNode:
    return AgentLineageNode(
        agent_id=record.agent_id,
        version=record.version,
        lifecycle_state=record.lifecycle_state,
        parent_agent_id=record.parent_agent_id,
    )


# ── Discovery ─────────────────────────────────────────────────────────────────
# NOTE: discovery is registered BEFORE the parameterised /{agent_id} routes so
# that "/discover" is not interpreted as a literal agent_id by FastAPI's router.


@router.get("/discover", response_model=list[AgentResponse])
async def discover_agents(
    capability: str | None = Query(
        default=None,
        description="Return only agents that declare this capability tag",
    ),
    lifecycle_state: LifecycleState | None = Query(
        default=None,
        description="Filter by lifecycle state (default: active or deprecated)",
    ),
    parent_agent_id: str | None = Query(
        default=None,
        description="Return only direct children of this parent agent",
    ),
    db: AsyncSession = Depends(get_db),
    principal: OperatorPrincipal = Depends(
        require_operator_roles("agent_admin", "auditor", "security_admin")
    ),
) -> list[AgentResponse]:
    """Discover agents by capability, lifecycle state, or parent."""
    records = await registry.discover_agents(
        db,
        capability=capability,
        lifecycle_state=lifecycle_state,
        parent_agent_id=parent_agent_id,
    )
    return [AgentResponse.model_validate(r) for r in records]


# ── CRUD ──────────────────────────────────────────────────────────────────────


@router.post("", response_model=AgentResponse, status_code=201)
async def register_agent(
    req: AgentRegisterRequest,
    db: AsyncSession = Depends(get_db),
    principal: OperatorPrincipal = Depends(require_operator_roles("agent_admin")),
) -> AgentResponse:
    """Register a new agent and return its manifest."""
    record = await registry.register_agent(db, req)
    # The next request may immediately issue a token on another connection.
    # Yield-dependency cleanup can occur after response delivery in FastAPI.
    await db.commit()
    await db.refresh(record)
    return AgentResponse.model_validate(record)


@router.get("", response_model=list[AgentResponse])
async def list_agents(
    db: AsyncSession = Depends(get_db),
    principal: OperatorPrincipal = Depends(
        require_operator_roles("agent_admin", "auditor", "security_admin")
    ),
) -> list[AgentResponse]:
    records = await registry.list_agents(db)
    return [AgentResponse.model_validate(r) for r in records]


@router.get("/{agent_id}", response_model=AgentResponse)
async def get_agent(
    agent_id: str,
    db: AsyncSession = Depends(get_db),
    principal: OperatorPrincipal = Depends(
        require_operator_roles("agent_admin", "auditor", "security_admin")
    ),
) -> AgentResponse:
    record = await registry.get_agent(db, agent_id)
    return AgentResponse.model_validate(record)


@router.put("/{agent_id}", response_model=AgentResponse)
async def update_agent(
    agent_id: str,
    req: AgentUpdateRequest,
    db: AsyncSession = Depends(get_db),
    principal: OperatorPrincipal = Depends(require_operator_roles("agent_admin")),
) -> AgentResponse:
    record = await registry.update_agent(db, agent_id, req)
    return AgentResponse.model_validate(record)


@router.delete("/{agent_id}", status_code=204)
async def deregister_agent(
    agent_id: str,
    db: AsyncSession = Depends(get_db),
    principal: OperatorPrincipal = Depends(require_operator_roles("agent_admin", "security_admin")),
) -> None:
    await registry.deregister_agent(db, agent_id)


# ── Lifecycle ─────────────────────────────────────────────────────────────────


@router.post("/{agent_id}/lifecycle", response_model=AgentResponse)
async def transition_lifecycle(
    agent_id: str,
    req: LifecycleTransitionRequest,
    db: AsyncSession = Depends(get_db),
    principal: OperatorPrincipal = Depends(require_operator_roles("agent_admin", "security_admin")),
) -> AgentResponse:
    """Move an agent into a new lifecycle state (draft/active/deprecated/retired)."""
    record = await registry.transition_lifecycle(db, agent_id, req.target_state)
    logger.info(
        "agent_lifecycle_transition",
        agent_id=agent_id,
        target_state=req.target_state,
        actor=principal.subject,
        reason=req.reason,
    )
    return AgentResponse.model_validate(record)


# ── Heartbeat ─────────────────────────────────────────────────────────────────


@router.post("/{agent_id}/heartbeat", response_model=AgentResponse)
async def heartbeat(
    agent_id: str,
    req: HeartbeatRequest = HeartbeatRequest(),
    db: AsyncSession = Depends(get_db),
    principal: OperatorPrincipal = Depends(
        require_operator_roles("agent_admin", "security_admin", "auditor")
    ),
) -> AgentResponse:
    """Record an agent heartbeat. Operators or the agent's runtime can call this."""
    record = await registry.record_heartbeat(db, agent_id, health_status=req.health_status)
    return AgentResponse.model_validate(record)


# ── Lineage ───────────────────────────────────────────────────────────────────


@router.get("/{agent_id}/lineage", response_model=AgentLineageResponse)
async def get_lineage(
    agent_id: str,
    db: AsyncSession = Depends(get_db),
    principal: OperatorPrincipal = Depends(
        require_operator_roles("agent_admin", "auditor", "security_admin")
    ),
) -> AgentLineageResponse:
    """Return the lineage chain (root → leaf) and direct children for an agent."""
    ancestors, children = await registry.get_lineage(db, agent_id)
    return AgentLineageResponse(
        agent_id=agent_id,
        ancestors=[_to_lineage_node(a) for a in ancestors],
        children=[_to_lineage_node(c) for c in children],
    )


# ── Token issuance ────────────────────────────────────────────────────────────


@router.post("/{agent_id}/token", response_model=TokenResponse)
async def issue_agent_token(
    agent_id: str,
    db: AsyncSession = Depends(get_db),
    principal: OperatorPrincipal = Depends(require_operator_roles("agent_admin")),
) -> TokenResponse:
    """Issue a short-lived JWT for an agent. Rate-limited to 10 requests per hour."""
    await _check_token_rate_limit(agent_id)
    # Verify agent exists, is active, and is in a token-eligible lifecycle state.
    await validate_agent_identity(db, agent_id, check_kill_switch=False)
    token, expires = issue_token(agent_id)
    return TokenResponse(agent_id=agent_id, access_token=token, expires_in_seconds=expires)
