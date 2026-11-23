from __future__ import annotations

import re
import secrets
from dataclasses import dataclass
from datetime import datetime

from fastapi import Depends, Request, Security
from fastapi.security import APIKeyCookie, APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession

from acr.common.errors import ForbiddenOperatorError, UnauthorizedOperatorError
from acr.common.oidc import decode_signed_payload, oidc_is_enabled, validate_oidc_token
from acr.common.time import utcnow
from acr.config import operator_api_keys
from acr.db.database import get_db
from acr.operator_keys.service import (
    find_operator_key_by_hash,
    hash_operator_key,
    touch_operator_key_usage,
)

_bearer_scheme = HTTPBearer(auto_error=False)
_operator_api_key_scheme = APIKeyHeader(name="X-Operator-API-Key", auto_error=False)
_operator_session_scheme = APIKeyCookie(name="acr_operator_session", auto_error=False)


@dataclass(frozen=True)
class OperatorPrincipal:
    subject: str
    roles: frozenset[str]
    source: str = "bootstrap"
    key_id: str | None = None
    # Set for time-boxed credentials (auditor grants, migration 0019).
    expires_at: datetime | None = None

    @property
    def is_auditor_only(self) -> bool:
        """True when the principal holds the auditor role and nothing else.

        A principal that also holds an operator role is an operator who
        can audit, not an auditor: the read-only scope below binds only
        auditor-only principals, which is exactly what an auditor grant
        issues (roles forced to {"auditor"} at creation).
        """
        return self.roles == frozenset({"auditor"})


# ── Auditor scope (v1.5.0 WS3) ────────────────────────────────────────────────
# Auditor access is enforced, not conventional: an auditor-only principal
# is rejected by every non-GET route and by every read surface outside
# the evidence scope, centrally, in require_operator_roles below — so a
# new route inherits the restriction by using the standard role
# dependency, and no route has to remember to check.
#
# In scope (GET only): decisions (explorer), agent manifests, policy
# releases, approvals, containment status/events, observe reports,
# simulation reports, telemetry events and per-correlation evidence.
# Out of scope: operator-key management, policy drafts, drift surfaces,
# session/config administration, and everything that mutates state.

_AUDITOR_EXACT_PATHS = frozenset(
    {
        "/acr/auth/session",
        "/console",
        "/openapi.json",
        "/docs",
        "/redoc",
        "/acr/decisions",
        "/acr/agents",
        "/acr/agents/discover",
        "/acr/policy-drafts/releases/history",
        "/acr/approvals",
        "/acr/containment/status",
        "/acr/events",
        "/acr/policy-bundles/active.tar.gz",
        "/acr/policy-bundles/discovery.json",
    }
)

_AUDITOR_PATH_PATTERNS = (
    re.compile(r"^/acr/decisions/chain/[^/]+$"),
    re.compile(r"^/acr/decisions/[^/]+$"),
    re.compile(r"^/acr/agents/[^/]+$"),
    re.compile(r"^/acr/agents/[^/]+/(lineage|observe-report)$"),
    re.compile(r"^/acr/policy-simulations/[^/]+(/summary\.md)?$"),
    re.compile(r"^/acr/approvals/[^/]+(/receipt)?$"),
    re.compile(r"^/acr/containment/status/[^/]+$"),
    re.compile(r"^/acr/events/[^/]+$"),
    re.compile(r"^/acr/evidence/[^/]+$"),
    re.compile(r"^/acr/policy-bundles/[^/]+/active\.tar\.gz$"),
)


def _auditor_path_allowed(path: str) -> bool:
    if path in _AUDITOR_EXACT_PATHS:
        return True
    return any(pattern.match(path) for pattern in _AUDITOR_PATH_PATTERNS)


def _enforce_auditor_scope(principal: OperatorPrincipal, request: Request | None) -> None:
    """Reject an auditor-only principal outside its read-only scope.

    Runs for every authentication source (database key, bootstrap key,
    OIDC bearer, signed session) once the principal is resolved, using
    the actual request method and path — route-level enforcement, not a
    UI convention.
    """
    if request is None or not principal.is_auditor_only:
        return
    if request.method.upper() not in ("GET", "HEAD"):
        raise ForbiddenOperatorError(
            "Auditor credentials are read-only: write operations are not permitted"
        )
    if not _auditor_path_allowed(request.url.path):
        raise ForbiddenOperatorError(f"Auditor credentials may not access '{request.url.path}'")


def _ensure_credential_not_expired(expires_at: datetime | None) -> None:
    if expires_at is None:
        return
    expiry = (
        expires_at if expires_at.tzinfo is not None else expires_at.replace(tzinfo=utcnow().tzinfo)
    )
    if expiry <= utcnow():
        raise UnauthorizedOperatorError("Operator credential has expired")


async def reject_auditor_operator_key(
    x_operator_api_key: str | None = Security(_operator_api_key_scheme),
    db: AsyncSession = Depends(get_db),
) -> None:
    """Guard for routes that do not use operator auth (the gateway).

    POST /acr/evaluate authenticates agents, not operators — but an
    auditor credential presented to it must still be rejected as an
    auditor (403), not silently treated as an unknown agent token. Any
    other operator key is ignored here: evaluate's own agent-token
    dependency decides the request.
    """
    if not x_operator_api_key:
        return
    record = await find_operator_key_by_hash(db, hash_operator_key(x_operator_api_key))
    if record is None:
        return
    if frozenset(str(role) for role in (record.roles or [])) == frozenset({"auditor"}):
        _ensure_credential_not_expired(record.expires_at)
        raise ForbiddenOperatorError(
            "Auditor credentials are read-only: write operations are not permitted"
        )


async def get_operator_principal(
    authorization: HTTPAuthorizationCredentials | None = Security(_bearer_scheme),
    x_operator_api_key: str | None = Security(_operator_api_key_scheme),
    acr_operator_session: str | None = Security(_operator_session_scheme),
    db: AsyncSession = Depends(get_db),
) -> OperatorPrincipal:
    if authorization and authorization.scheme.lower() == "bearer":
        oidc_principal = await validate_oidc_token(authorization.credentials)
        return OperatorPrincipal(
            subject=oidc_principal.subject,
            roles=oidc_principal.roles,
            source="oidc_bearer",
        )

    if acr_operator_session:
        try:
            session_payload = decode_signed_payload(acr_operator_session)
        except Exception as exc:
            raise UnauthorizedOperatorError("Operator session is invalid") from exc
        return OperatorPrincipal(
            subject=str(session_payload.get("subject") or "operator"),
            roles=frozenset(str(role) for role in (session_payload.get("roles") or [])),
            source=str(session_payload.get("source") or "oidc_session"),
        )

    if not x_operator_api_key:
        if oidc_is_enabled():
            raise UnauthorizedOperatorError(
                "Operator authentication required via OIDC session, Bearer token, or X-Operator-API-Key"
            )
        raise UnauthorizedOperatorError("X-Operator-API-Key header is required")

    db_record = await find_operator_key_by_hash(db, hash_operator_key(x_operator_api_key))
    if db_record is not None:
        # Expiry is checked before the usage touch: an expired grant
        # rejects everywhere, including surfaces it could read yesterday.
        _ensure_credential_not_expired(db_record.expires_at)
        await touch_operator_key_usage(db, db_record)
        return OperatorPrincipal(
            subject=db_record.subject,
            roles=frozenset(str(role) for role in (db_record.roles or [])),
            source="database",
            key_id=db_record.key_id,
            expires_at=db_record.expires_at,
        )

    for expected_key, identity in operator_api_keys().items():
        if secrets.compare_digest(x_operator_api_key, expected_key):
            subject = str(identity.get("subject") or "operator")
            roles = identity.get("roles") or []
            if not isinstance(roles, list):
                raise UnauthorizedOperatorError("Operator roles configuration is invalid")
            return OperatorPrincipal(
                subject=subject,
                roles=frozenset(str(r) for r in roles),
                source="bootstrap",
            )

    raise UnauthorizedOperatorError("Operator API key is invalid")


def require_operator_roles(*required_roles: str):
    async def _dependency(
        request: Request,
        principal: OperatorPrincipal = Depends(get_operator_principal),
    ) -> OperatorPrincipal:
        # Central auditor-scope enforcement: every role-gated route runs
        # through here, so an auditor-only principal is confined to its
        # read-only evidence scope on all of them (WS3). The two routes
        # that depend on get_operator_principal directly (session,
        # console) are both inside the auditor's allowed path set.
        _enforce_auditor_scope(principal, request)
        if required_roles and principal.roles.isdisjoint(required_roles):
            raise ForbiddenOperatorError(
                f"Operator '{principal.subject}' lacks one of the required roles: "
                f"{', '.join(required_roles)}"
            )
        return principal

    return _dependency
