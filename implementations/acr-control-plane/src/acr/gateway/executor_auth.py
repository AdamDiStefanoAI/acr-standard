from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
from fastapi import Header, Request
from jwt import ExpiredSignatureError, PyJWTError

from acr.common.errors import InvalidExecutionAuthorizationError
from acr.common.jwt_validation import decode_jwt
from acr.config import settings

_EXECUTION_TOKEN_ALGORITHM = "HS256"
_EXECUTION_TOKEN_ISSUER = "acr-control-plane"


@dataclass(frozen=True)
class ExecutionAuthorization:
    agent_id: str
    tool_name: str
    correlation_id: str
    approval_request_id: str | None
    payload_sha256: str


@dataclass(frozen=True)
class BrokeredExecutionCredential:
    subject: str
    agent_id: str
    tool_name: str
    correlation_id: str
    audience: str
    scopes: tuple[str, ...]
    approval_request_id: str | None
    payload_sha256: str


def canonicalize_execution_payload(payload: dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def execution_payload_sha256(payload: dict[str, Any]) -> str:
    return hashlib.sha256(canonicalize_execution_payload(payload).encode()).hexdigest()


def _require_execution_secret() -> str:
    secret = settings.executor_hmac_secret.strip()
    if not secret:
        raise InvalidExecutionAuthorizationError(
            "Gateway execution authorization is not configured"
        )
    return secret


def _require_credential_secret() -> str:
    secret = settings.executor_credential_secret.strip()
    if not secret:
        raise InvalidExecutionAuthorizationError(
            "Brokered downstream credentials are not configured"
        )
    return secret


def build_execution_token(
    *,
    agent_id: str,
    tool_name: str,
    correlation_id: str,
    payload: dict[str, Any],
    approval_request_id: str | None = None,
) -> str:
    secret = _require_execution_secret()
    now = datetime.now(UTC)
    claims = {
        "iss": _EXECUTION_TOKEN_ISSUER,
        "sub": tool_name,
        "agent_id": agent_id,
        "tool_name": tool_name,
        "correlation_id": correlation_id,
        "approval_request_id": approval_request_id,
        "payload_sha256": execution_payload_sha256(payload),
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=settings.executor_auth_ttl_seconds)).timestamp()),
    }
    return jwt.encode(claims, secret, algorithm=_EXECUTION_TOKEN_ALGORITHM)


def build_execution_headers(
    *,
    agent_id: str,
    tool_name: str,
    payload: dict[str, Any],
    correlation_id: str,
    approval_request_id: str | None = None,
) -> dict[str, str]:
    headers = {
        "Content-Type": "application/json",
        "X-Correlation-ID": correlation_id,
        "Idempotency-Key": correlation_id,
    }
    secret = settings.executor_hmac_secret.strip()
    if not secret:
        return headers

    body = canonicalize_execution_payload(payload)
    signature = hmac.new(secret.encode(), body.encode(), hashlib.sha256).hexdigest()
    headers["X-ACR-Execution-Signature"] = signature
    headers["X-ACR-Execution-Token"] = build_execution_token(
        agent_id=agent_id,
        tool_name=tool_name,
        correlation_id=correlation_id,
        payload=payload,
        approval_request_id=approval_request_id,
    )
    return headers


def build_brokered_execution_credential(
    *,
    agent_id: str,
    tool_name: str,
    correlation_id: str,
    audience: str,
    scopes: list[str] | tuple[str, ...],
    payload: dict[str, Any],
    approval_request_id: str | None = None,
) -> str:
    """Mint a brokered credential bound to one exact execution payload.

    The payload hash claim is mandatory: without it, a credential minted for
    one payload could be replayed with a different payload on the
    gateway-to-executor path. This mirrors the binding X-ACR-Execution-Token
    has always carried.
    """
    secret = _require_credential_secret()
    now = datetime.now(UTC)
    claims = {
        "iss": _EXECUTION_TOKEN_ISSUER,
        "sub": f"acr-executor:{agent_id}:{tool_name}",
        "agent_id": agent_id,
        "tool_name": tool_name,
        "correlation_id": correlation_id,
        "approval_request_id": approval_request_id,
        "aud": audience,
        "scopes": list(scopes),
        "payload_sha256": execution_payload_sha256(payload),
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=settings.executor_credential_ttl_seconds)).timestamp()),
    }
    return jwt.encode(claims, secret, algorithm=_EXECUTION_TOKEN_ALGORITHM)


def verify_brokered_execution_credential(
    token: str,
    *,
    audience: str,
    payload: dict[str, Any] | None = None,
) -> BrokeredExecutionCredential:
    """Verify a brokered credential. When `payload` is given, the credential
    must be bound to exactly that payload; credentials minted before payload
    binding existed carry no hash claim and are rejected on this path."""
    secret = _require_credential_secret()
    try:
        claims = decode_jwt(
            token,
            secret,
            algorithms=[_EXECUTION_TOKEN_ALGORITHM],
            issuer=_EXECUTION_TOKEN_ISSUER,
            audience=audience,
        )
    except ExpiredSignatureError as exc:
        raise InvalidExecutionAuthorizationError(
            "Brokered execution credential has expired"
        ) from exc
    except PyJWTError as exc:
        raise InvalidExecutionAuthorizationError(
            "Brokered execution credential is invalid"
        ) from exc

    scopes_raw = claims.get("scopes") or []
    if not isinstance(scopes_raw, list):
        raise InvalidExecutionAuthorizationError("Brokered execution credential scopes are invalid")

    agent_id = str(claims.get("agent_id") or "")
    tool_name = str(claims.get("tool_name") or "")
    correlation_id = str(claims.get("correlation_id") or "")
    subject = str(claims.get("sub") or "")
    if not agent_id or not tool_name or not correlation_id or not subject:
        raise InvalidExecutionAuthorizationError(
            "Brokered execution credential is missing required claims"
        )

    payload_sha256 = str(claims.get("payload_sha256") or "")
    if payload is not None:
        if not payload_sha256:
            raise InvalidExecutionAuthorizationError(
                "Brokered execution credential is not bound to a payload"
            )
        if not hmac.compare_digest(execution_payload_sha256(payload), payload_sha256):
            raise InvalidExecutionAuthorizationError(
                "Brokered execution credential does not match the request payload"
            )

    approval_request_id = claims.get("approval_request_id")
    return BrokeredExecutionCredential(
        subject=subject,
        agent_id=agent_id,
        tool_name=tool_name,
        correlation_id=correlation_id,
        audience=audience,
        scopes=tuple(str(scope) for scope in scopes_raw),
        approval_request_id=str(approval_request_id) if approval_request_id else None,
        payload_sha256=payload_sha256,
    )


def verify_execution_token(
    token: str,
    *,
    payload: dict[str, Any],
) -> ExecutionAuthorization:
    secret = _require_execution_secret()
    try:
        claims = decode_jwt(
            token,
            secret,
            algorithms=[_EXECUTION_TOKEN_ALGORITHM],
            issuer=_EXECUTION_TOKEN_ISSUER,
        )
    except ExpiredSignatureError as exc:
        raise InvalidExecutionAuthorizationError(
            "Execution authorization token has expired"
        ) from exc
    except PyJWTError as exc:
        raise InvalidExecutionAuthorizationError(
            "Execution authorization token is invalid"
        ) from exc

    expected_hash = execution_payload_sha256(payload)
    actual_hash = str(claims.get("payload_sha256") or "")
    if not hmac.compare_digest(expected_hash, actual_hash):
        raise InvalidExecutionAuthorizationError(
            "Execution authorization does not match the request payload"
        )

    agent_id = str(claims.get("agent_id") or "")
    tool_name = str(claims.get("tool_name") or "")
    correlation_id = str(claims.get("correlation_id") or "")
    if not agent_id or not tool_name or not correlation_id:
        raise InvalidExecutionAuthorizationError(
            "Execution authorization token is missing required claims"
        )

    approval_request_id = claims.get("approval_request_id")
    return ExecutionAuthorization(
        agent_id=agent_id,
        tool_name=tool_name,
        correlation_id=correlation_id,
        approval_request_id=str(approval_request_id) if approval_request_id else None,
        payload_sha256=actual_hash,
    )


async def require_gateway_execution(
    request: Request,
    x_acr_execution_token: str | None = Header(default=None),
) -> ExecutionAuthorization:
    if not x_acr_execution_token:
        raise InvalidExecutionAuthorizationError("X-ACR-Execution-Token header is required")

    try:
        payload = await request.json()
    except json.JSONDecodeError as exc:
        raise InvalidExecutionAuthorizationError(
            "Execution request body must be valid JSON"
        ) from exc

    if not isinstance(payload, dict):
        raise InvalidExecutionAuthorizationError("Execution request body must be a JSON object")

    return verify_execution_token(x_acr_execution_token, payload=payload)


async def require_brokered_execution_credential(
    request: Request,
    x_acr_brokered_credential: str | None = Header(default=None),
    x_acr_credential_audience: str | None = Header(default=None),
) -> BrokeredExecutionCredential:
    if not x_acr_brokered_credential:
        raise InvalidExecutionAuthorizationError("X-ACR-Brokered-Credential header is required")
    if not x_acr_credential_audience:
        raise InvalidExecutionAuthorizationError("X-ACR-Credential-Audience header is required")

    try:
        payload = await request.json()
    except json.JSONDecodeError as exc:
        raise InvalidExecutionAuthorizationError(
            "Execution request body must be valid JSON"
        ) from exc

    if not isinstance(payload, dict):
        raise InvalidExecutionAuthorizationError("Execution request body must be a JSON object")

    return verify_brokered_execution_credential(
        x_acr_brokered_credential,
        audience=x_acr_credential_audience,
        payload=payload,
    )
