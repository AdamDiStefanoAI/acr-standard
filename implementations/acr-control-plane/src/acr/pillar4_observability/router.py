"""Pillar 4: Auditor surface API (v1.5.0 WS3).

Decision explorer (list + full chain) and the evidence package
generator endpoint. Reads are open to the auditor role; package
generation is an operator action (agent_admin / security_admin) and is
audited by the generator. Auditor-only principals are additionally
confined by the central scope guard in acr.common.operator_auth.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from fastapi import APIRouter, Depends, Query
from fastapi.responses import Response
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from acr.common.errors import PolicyValidationError
from acr.common.operator_auth import OperatorPrincipal, require_operator_roles
from acr.db.database import get_db
from acr.pillar4_observability import explorer
from acr.pillar4_observability.evidence_package import generate_evidence_package
from acr.pillar4_observability.explorer import DecisionChain, DecisionListResponse

router = APIRouter(tags=["Auditor Surface"])

_READ_ROLES = ("auditor", "agent_admin", "security_admin", "approver")


@router.get("/acr/decisions", response_model=DecisionListResponse)
async def list_decisions(
    agent_id: str | None = Query(default=None),
    window_start: datetime | None = Query(default=None),
    window_end: datetime | None = Query(default=None),
    decision: Literal["allow", "deny", "modify", "escalate"] | None = Query(default=None),
    enforcement_mode: Literal["enforce", "observe"] | None = Query(default=None),
    reason_contains: str | None = Query(default=None),
    tool_name: str | None = Query(default=None),
    correlation_id: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: AsyncSession = Depends(get_db),
    principal: OperatorPrincipal = Depends(require_operator_roles(*_READ_ROLES)),
) -> DecisionListResponse:
    if window_start and window_end and window_start > window_end:
        raise PolicyValidationError("window_start must be at or before window_end")
    return await explorer.list_decisions(
        db,
        actor=principal.subject,
        agent_id=agent_id,
        window_start=window_start,
        window_end=window_end,
        decision=decision,
        enforcement_mode=enforcement_mode,
        reason_contains=reason_contains,
        tool_name=tool_name,
        correlation_id=correlation_id,
        limit=limit,
        offset=offset,
    )


@router.get("/acr/decisions/chain/{identifier}", response_model=DecisionChain)
async def get_decision_chain(
    identifier: str,
    db: AsyncSession = Depends(get_db),
    principal: OperatorPrincipal = Depends(require_operator_roles(*_READ_ROLES)),
) -> DecisionChain:
    """Full chain for one action, by correlation_id or decision id."""
    return await explorer.get_decision_chain(db, actor=principal.subject, identifier=identifier)


class EvidencePackageRequest(BaseModel):
    window_start: datetime
    window_end: datetime


@router.post("/acr/evidence-packages")
async def create_evidence_package(
    body: EvidencePackageRequest,
    db: AsyncSession = Depends(get_db),
    principal: OperatorPrincipal = Depends(require_operator_roles("agent_admin", "security_admin")),
) -> Response:
    """Generate an evidence package for a window and download it as a zip.

    Generation is an operator action and is written to the audit log by
    the generator (actor, window, chain head, package hash).
    """
    if body.window_start > body.window_end:
        raise PolicyValidationError("window_start must be at or before window_end")
    artifact = await generate_evidence_package(
        db,
        actor=principal.subject,
        window_start=body.window_start,
        window_end=body.window_end,
    )
    return Response(
        content=artifact.bytes_data,
        media_type=artifact.content_type,
        headers={
            "Content-Disposition": f'attachment; filename="{artifact.filename}"',
            "X-Evidence-Package-Sha256": artifact.sha256,
            "X-Evidence-Chain-Head": artifact.chain_head_sha256,
        },
    )
