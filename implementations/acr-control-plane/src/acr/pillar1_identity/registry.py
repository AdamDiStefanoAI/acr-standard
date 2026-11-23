"""Pillar 1: Agent registry — CRUD backed by PostgreSQL.

The registry stores agent identity, manifest, lineage, capabilities, lifecycle
state and health. It is the authoritative source for the gateway's identity
checks and the discovery API.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from acr.common.errors import (
    AgentAlreadyExistsError,
    AgentLifecycleError,
    AgentNotFoundError,
)
from acr.common.time import utcnow
from acr.db.models import AgentRecord
from acr.pillar1_identity.models import (
    AgentBoundaries,
    AgentManifest,
    AgentRegisterRequest,
    AgentUpdateRequest,
    EnforcementMode,
    HealthStatus,
    LifecycleState,
)

# Lifecycle states in which the agent is allowed to call /acr/evaluate.
# `deprecated` is allowed but a warning is emitted by the gateway hot path.
ACTIVE_LIFECYCLE_STATES: frozenset[str] = frozenset({"active", "deprecated"})

# Allowed lifecycle transitions. Retired is terminal — once retired an agent
# must be re-registered (this prevents accidental "un-retirement" and gives
# auditors a clean signal that an agent has truly been decommissioned).
LIFECYCLE_TRANSITIONS: dict[str, frozenset[str]] = {
    "draft": frozenset({"active", "retired"}),
    "active": frozenset({"deprecated", "retired"}),
    "deprecated": frozenset({"active", "retired"}),
    "retired": frozenset(),  # terminal
}


def _record_to_manifest(record: AgentRecord) -> AgentManifest:
    return AgentManifest(
        agent_id=record.agent_id,
        owner=record.owner,
        purpose=record.purpose,
        risk_tier=record.risk_tier,
        allowed_tools=record.allowed_tools or [],
        forbidden_tools=record.forbidden_tools or [],
        data_access=record.data_access or [],
        boundaries=AgentBoundaries(**(record.boundaries or {})),
        version=record.version,
        parent_agent_id=record.parent_agent_id,
        capabilities=record.capabilities or [],
        enforcement_mode=record.enforcement_mode,
    )


async def register_agent(db: AsyncSession, req: AgentRegisterRequest) -> AgentRecord:
    """Insert a new agent record. Returns the ORM record.

    If `parent_agent_id` is supplied, the parent must already exist and must
    not be in the `retired` state — otherwise lineage would be ambiguous.
    """
    if req.parent_agent_id is not None:
        parent = await get_agent(db, req.parent_agent_id)
        if parent.lifecycle_state == "retired":
            raise AgentLifecycleError(
                f"Cannot attach new agent to retired parent '{req.parent_agent_id}'"
            )

    record = AgentRecord(
        agent_id=req.agent_id,
        owner=req.owner,
        purpose=req.purpose,
        risk_tier=req.risk_tier,
        allowed_tools=req.allowed_tools,
        forbidden_tools=req.forbidden_tools,
        data_access=[e.model_dump() for e in req.data_access],
        boundaries=req.boundaries.model_dump(),
        version=req.version,
        parent_agent_id=req.parent_agent_id,
        capabilities=req.capabilities,
        lifecycle_state=req.lifecycle_state,
        enforcement_mode=req.enforcement_mode,
        # Keep legacy is_active in sync with lifecycle_state. Existing
        # consumers (validator, metrics, gateway) still read is_active.
        is_active=(req.lifecycle_state != "retired"),
    )
    db.add(record)
    try:
        await db.flush()
    except IntegrityError as exc:
        await db.rollback()
        raise AgentAlreadyExistsError(f"Agent '{req.agent_id}' is already registered") from exc
    await db.refresh(record)
    return record


async def get_agent(db: AsyncSession, agent_id: str) -> AgentRecord:
    result = await db.execute(select(AgentRecord).where(AgentRecord.agent_id == agent_id))
    record = result.scalar_one_or_none()
    if record is None:
        raise AgentNotFoundError(f"Agent '{agent_id}' not found")
    return record


async def list_agents(db: AsyncSession) -> list[AgentRecord]:
    result = await db.execute(select(AgentRecord).order_by(AgentRecord.created_at.desc()))
    return list(result.scalars().all())


async def update_agent(db: AsyncSession, agent_id: str, req: AgentUpdateRequest) -> AgentRecord:
    record = await get_agent(db, agent_id)
    if req.owner is not None:
        record.owner = req.owner
    if req.purpose is not None:
        record.purpose = req.purpose
    if req.risk_tier is not None:
        record.risk_tier = req.risk_tier
    if req.allowed_tools is not None:
        record.allowed_tools = req.allowed_tools
    if req.forbidden_tools is not None:
        record.forbidden_tools = req.forbidden_tools
    if req.data_access is not None:
        record.data_access = [e.model_dump() for e in req.data_access]
    if req.boundaries is not None:
        record.boundaries = req.boundaries.model_dump()
    if req.version is not None:
        record.version = req.version
    if req.capabilities is not None:
        record.capabilities = req.capabilities
    record.updated_at = utcnow()
    await db.flush()
    await db.refresh(record)
    return record


async def deregister_agent(db: AsyncSession, agent_id: str) -> None:
    """Deregister an agent.

    For backwards compatibility this still flips `is_active=False`, but it
    also moves the agent to the terminal `retired` lifecycle state so the
    new validator path blocks evaluate calls correctly.
    """
    record = await get_agent(db, agent_id)
    record.is_active = False
    record.lifecycle_state = "retired"
    await db.flush()


async def transition_lifecycle(
    db: AsyncSession,
    agent_id: str,
    target_state: LifecycleState,
) -> AgentRecord:
    """Move an agent into a new lifecycle state.

    Validates the transition against `LIFECYCLE_TRANSITIONS`. The legacy
    `is_active` flag is kept consistent (False ⇔ retired).
    """
    record = await get_agent(db, agent_id)
    current = record.lifecycle_state
    if target_state == current:
        return record
    allowed = LIFECYCLE_TRANSITIONS.get(current, frozenset())
    if target_state not in allowed:
        raise AgentLifecycleError(
            f"Illegal lifecycle transition for agent '{agent_id}': {current} → {target_state}"
        )
    record.lifecycle_state = target_state
    record.is_active = target_state != "retired"
    record.updated_at = utcnow()
    await db.flush()
    await db.refresh(record)
    return record


async def transition_enforcement_mode(
    db: AsyncSession,
    agent_id: str,
    target_mode: EnforcementMode,
) -> AgentRecord:
    """Move an agent between `enforce` and `observe` enforcement modes.

    This is the ONLY write path for enforcement mode after registration:
    the generic update endpoint deliberately does not carry the field, and
    the gateway reads mode exclusively from the stored record. Both
    directions are allowed (pilots promote observe → enforce and may step
    back). Retired agents are terminal, consistent with lifecycle rules —
    their mode can no longer change.

    Mode flips do not reach into pillar 6: approval requests already in
    the queue keep the lifecycle, expiry and claim-once receipt semantics
    they were issued under, in both directions.
    """
    record = await get_agent(db, agent_id)
    if record.enforcement_mode == target_mode:
        return record
    if record.lifecycle_state == "retired":
        raise AgentLifecycleError(f"Cannot change enforcement mode of retired agent '{agent_id}'")
    record.enforcement_mode = target_mode
    record.updated_at = utcnow()
    await db.flush()
    await db.refresh(record)
    return record


async def record_heartbeat(
    db: AsyncSession,
    agent_id: str,
    health_status: HealthStatus = "healthy",
) -> AgentRecord:
    """Update the agent's last heartbeat timestamp and health status.

    Heartbeats from a `retired` agent are rejected — that's a strong signal
    something is wrong (a decommissioned agent should not be running) and
    the gateway should not silently treat it as healthy.
    """
    record = await get_agent(db, agent_id)
    if record.lifecycle_state == "retired":
        raise AgentLifecycleError(f"Heartbeat received from retired agent '{agent_id}'")
    record.last_heartbeat_at = utcnow()
    record.health_status = health_status
    await db.flush()
    await db.refresh(record)
    return record


async def discover_agents(
    db: AsyncSession,
    *,
    capability: str | None = None,
    lifecycle_state: LifecycleState | None = None,
    parent_agent_id: str | None = None,
) -> list[AgentRecord]:
    """Discover agents matching one or more selectors.

    By default returns only agents in an "active-ish" lifecycle state
    (active or deprecated) so callers don't accidentally route work to
    drafts or retired agents. Pass an explicit `lifecycle_state` to
    override that filter.

    NOTE: capability filtering is performed in Python rather than via a
    JSON containment operator. This keeps the function portable across
    Postgres / SQLite (tests use SQLite). For very large registries this
    should be replaced with a Postgres `jsonb @>` query.
    """
    query = select(AgentRecord)
    if lifecycle_state is None:
        query = query.where(
            or_(
                AgentRecord.lifecycle_state == "active",
                AgentRecord.lifecycle_state == "deprecated",
            )
        )
    else:
        query = query.where(AgentRecord.lifecycle_state == lifecycle_state)
    if parent_agent_id is not None:
        query = query.where(AgentRecord.parent_agent_id == parent_agent_id)
    query = query.order_by(AgentRecord.created_at.desc())

    result = await db.execute(query)
    records = list(result.scalars().all())

    if capability is not None:
        records = [r for r in records if capability in (r.capabilities or [])]
    return records


async def get_lineage(
    db: AsyncSession, agent_id: str
) -> tuple[list[AgentRecord], list[AgentRecord]]:
    """Return (ancestors_root_to_leaf, direct_children) for an agent.

    Walks parents iteratively (cycle-safe) and fetches direct children in
    a single query. The chain includes the queried agent as the final
    element of `ancestors`.
    """
    leaf = await get_agent(db, agent_id)

    chain: list[AgentRecord] = [leaf]
    seen: set[str] = {leaf.agent_id}
    cursor: AgentRecord = leaf
    # Cap depth defensively in case of corrupted data — lineage chains
    # should never be deeper than a handful of levels in practice.
    for _ in range(32):
        if cursor.parent_agent_id is None:
            break
        if cursor.parent_agent_id in seen:
            # cycle detection — don't loop forever
            break
        try:
            parent = await get_agent(db, cursor.parent_agent_id)
        except AgentNotFoundError:
            break
        chain.append(parent)
        seen.add(parent.agent_id)
        cursor = parent

    ancestors = list(reversed(chain))  # root → leaf

    children_result = await db.execute(
        select(AgentRecord)
        .where(AgentRecord.parent_agent_id == agent_id)
        .order_by(AgentRecord.created_at.asc())
    )
    children = list(children_result.scalars().all())
    return ancestors, children


async def sweep_stale_heartbeats(
    db: AsyncSession,
    *,
    threshold_seconds: int,
) -> int:
    """Mark `active` agents as `unhealthy` if their last heartbeat is stale.

    Agents that have never sent a heartbeat (last_heartbeat_at IS NULL) are
    deliberately *not* downgraded — they remain `unknown`. This keeps agents
    that don't opt into heartbeats from being misreported as unhealthy.

    Returns the number of agents downgraded.
    """
    cutoff = datetime.now(UTC) - timedelta(seconds=threshold_seconds)
    result = await db.execute(
        select(AgentRecord).where(
            AgentRecord.lifecycle_state.in_(("active", "deprecated")),
            AgentRecord.last_heartbeat_at.is_not(None),
            AgentRecord.last_heartbeat_at < cutoff,
            AgentRecord.health_status != "unhealthy",
        )
    )
    downgraded = 0
    for record in result.scalars().all():
        record.health_status = "unhealthy"
        downgraded += 1
    if downgraded:
        await db.flush()
    return downgraded


async def get_manifest(db: AsyncSession, agent_id: str) -> AgentManifest:
    record = await get_agent(db, agent_id)
    return _record_to_manifest(record)
