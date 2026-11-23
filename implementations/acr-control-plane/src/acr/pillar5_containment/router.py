"""Pillar 5: Operator-facing containment API proxied through the gateway."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from acr.common.operator_auth import OperatorPrincipal, require_operator_roles
from acr.db.database import get_db
from acr.pillar5_containment.killswitch import (
    get_kill_status,
    kill_agent,
    list_kill_status,
    restore_agent,
)
from acr.pillar5_containment.models import KillRequest, KillSwitchState, RestoreRequest

router = APIRouter(prefix="/acr/containment", tags=["Containment"])


@router.post("/kill", response_model=KillSwitchState)
async def kill(
    body: KillRequest,
    db: AsyncSession = Depends(get_db),
    principal: OperatorPrincipal = Depends(
        require_operator_roles("security_admin", "killswitch_operator")
    ),
) -> KillSwitchState:
    state = await kill_agent(
        body.agent_id,
        reason=body.reason,
        operator_id=body.operator_id or principal.subject,
    )
    # Integration alerts (v1.5.0 WS4): async outbox, best-effort — the
    # kill has already taken effect; alerting can never affect it.
    from acr.integrations.events import notify_killswitch

    await notify_killswitch(
        db,
        agent_id=body.agent_id,
        reason=body.reason,
        operator_id=body.operator_id or principal.subject,
    )
    await db.commit()
    return state


@router.post("/restore", response_model=KillSwitchState)
async def restore(
    body: RestoreRequest,
    principal: OperatorPrincipal = Depends(
        require_operator_roles("security_admin", "killswitch_operator")
    ),
) -> KillSwitchState:
    return await restore_agent(
        body.agent_id,
        operator_id=body.operator_id or principal.subject,
    )


@router.get("/status/{agent_id}", response_model=KillSwitchState)
async def status(
    agent_id: str,
    principal: OperatorPrincipal = Depends(
        require_operator_roles("security_admin", "killswitch_operator", "auditor")
    ),
) -> KillSwitchState:
    return await get_kill_status(agent_id)


@router.get("/status", response_model=list[KillSwitchState])
async def status_list(
    principal: OperatorPrincipal = Depends(
        require_operator_roles("security_admin", "killswitch_operator", "auditor")
    ),
) -> list[KillSwitchState]:
    return await list_kill_status()
