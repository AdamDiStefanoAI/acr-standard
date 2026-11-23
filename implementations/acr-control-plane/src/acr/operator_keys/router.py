from __future__ import annotations

import structlog
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from acr.common.operator_auth import OperatorPrincipal, require_operator_roles
from acr.db.database import get_db
from acr.operator_keys import service
from acr.operator_keys.models import (
    AuditorGrantCreateRequest,
    OperatorKeyCreateRequest,
    OperatorKeyCreateResponse,
    OperatorKeyResponse,
)

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/acr/operator-keys", tags=["Operator Keys"])


def _to_response(record) -> OperatorKeyResponse:
    return OperatorKeyResponse.model_validate(record)


@router.get("", response_model=list[OperatorKeyResponse])
async def list_keys(
    db: AsyncSession = Depends(get_db),
    principal: OperatorPrincipal = Depends(require_operator_roles("security_admin")),
) -> list[OperatorKeyResponse]:
    records = await service.list_operator_keys(db)
    return [_to_response(record) for record in records]


@router.post("", response_model=OperatorKeyCreateResponse, status_code=201)
async def create_key(
    body: OperatorKeyCreateRequest,
    db: AsyncSession = Depends(get_db),
    principal: OperatorPrincipal = Depends(require_operator_roles("security_admin")),
) -> OperatorKeyCreateResponse:
    record, api_key = await service.create_operator_key(
        db,
        req=body,
        created_by=principal.subject,
    )
    return OperatorKeyCreateResponse(
        api_key=api_key, **OperatorKeyResponse.model_validate(record).model_dump()
    )


@router.post("/auditor-grants", response_model=OperatorKeyCreateResponse, status_code=201)
async def create_auditor_grant(
    body: AuditorGrantCreateRequest,
    db: AsyncSession = Depends(get_db),
    principal: OperatorPrincipal = Depends(require_operator_roles("security_admin")),
) -> OperatorKeyCreateResponse:
    """Issue a time-boxed, read-only auditor grant (security_admin only).

    The grant is an operator credential with roles forced to exactly
    ["auditor"] and a mandatory expiry. Issuance is written to the audit
    log with the grant's subject, key id, and expiry.
    """
    record, api_key = await service.create_auditor_grant(
        db,
        req=body,
        created_by=principal.subject,
    )
    await db.commit()
    await db.refresh(record)
    logger.info(
        "auditor_grant_issued",
        key_id=record.key_id,
        subject=record.subject,
        expires_at=record.expires_at.isoformat() if record.expires_at else None,
        actor=principal.subject,
    )
    return OperatorKeyCreateResponse(
        **_to_response(record).model_dump(),
        api_key=api_key,
    )


@router.post("/{key_id}/revoke", response_model=OperatorKeyResponse)
async def revoke_key(
    key_id: str,
    db: AsyncSession = Depends(get_db),
    principal: OperatorPrincipal = Depends(require_operator_roles("security_admin")),
) -> OperatorKeyResponse:
    record = await service.revoke_operator_key(db, key_id=key_id, revoked_by=principal.subject)
    if list(record.roles or []) == ["auditor"]:
        logger.info(
            "auditor_grant_revoked",
            key_id=record.key_id,
            subject=record.subject,
            actor=principal.subject,
        )
    return _to_response(record)


@router.post("/{key_id}/rotate", response_model=OperatorKeyCreateResponse)
async def rotate_key(
    key_id: str,
    db: AsyncSession = Depends(get_db),
    principal: OperatorPrincipal = Depends(require_operator_roles("security_admin")),
) -> OperatorKeyCreateResponse:
    record, api_key = await service.rotate_operator_key(
        db, key_id=key_id, rotated_by=principal.subject
    )
    return OperatorKeyCreateResponse(
        api_key=api_key, **OperatorKeyResponse.model_validate(record).model_dump()
    )
