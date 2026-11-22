from __future__ import annotations

import os
from typing import Any

import httpx

from acr.common.errors import DownstreamExecutionError
from acr.config import settings
from acr.gateway.executor_auth import build_brokered_execution_credential, build_execution_headers


def _integration_headers(
    config: dict[str, Any],
    *,
    agent_id: str,
    tool_name: str,
    payload: dict[str, Any],
    correlation_id: str,
    approval_request_id: str | None,
) -> dict[str, str]:
    headers = build_execution_headers(
        agent_id=agent_id,
        tool_name=tool_name,
        payload=payload,
        correlation_id=correlation_id,
        approval_request_id=approval_request_id,
    )
    broker_cfg = config.get("broker_credentials") or {}
    if settings.executor_credential_secret and isinstance(broker_cfg, dict):
        audience = str(broker_cfg.get("audience") or f"tool:{tool_name}")
        scopes_raw = broker_cfg.get("scopes") or [f"tool:{tool_name}:execute"]
        if not isinstance(scopes_raw, list):
            raise DownstreamExecutionError("broker_credentials.scopes must be an array")
        headers["X-ACR-Credential-Audience"] = audience
        headers["X-ACR-Brokered-Credential"] = build_brokered_execution_credential(
            agent_id=agent_id,
            tool_name=tool_name,
            correlation_id=correlation_id,
            audience=audience,
            scopes=[str(scope) for scope in scopes_raw],
            payload=payload,
            approval_request_id=approval_request_id,
        )
    api_key = _resolve_secret_value(str(config.get("api_key") or "").strip())
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    return headers


def _resolve_secret_value(value: str) -> str:
    if value.startswith("env:"):
        return os.getenv(value.removeprefix("env:"), "")
    return value


def _require_url(config: dict[str, Any], provider: str) -> str:
    url = str(config.get("url") or "").strip()
    if not url:
        raise DownstreamExecutionError(
            f"Executor integration provider '{provider}' requires a configured url"
        )
    return url


def _build_provider_payload(
    *,
    provider: str,
    agent_id: str,
    tool_name: str,
    parameters: dict,
    description: str | None,
    correlation_id: str,
    approval_request_id: str | None,
    config: dict[str, Any],
) -> dict[str, Any]:
    if provider == "refund_api":
        return {
            "agent_id": agent_id,
            "refund_request": {
                "customer_id": parameters.get("customer_id"),
                "order_id": parameters.get("order_id"),
                "amount": parameters.get("amount"),
                "currency": parameters.get("currency") or config.get("default_currency", "USD"),
                "reason": description or parameters.get("reason"),
            },
            "correlation_id": correlation_id,
            "approval_request_id": approval_request_id,
        }
    if provider == "email_api":
        return {
            "agent_id": agent_id,
            "message": {
                "from": config.get("from_address"),
                "to": parameters.get("to"),
                "cc": parameters.get("cc"),
                "subject": parameters.get("subject"),
                "body": parameters.get("body"),
                "template_id": parameters.get("template_id"),
            },
            "correlation_id": correlation_id,
            "approval_request_id": approval_request_id,
        }
    if provider == "ticket_api":
        return {
            "agent_id": agent_id,
            "ticket": {
                "external_id": parameters.get("ticket_id"),
                "title": parameters.get("title") or description,
                "body": parameters.get("body"),
                "priority": parameters.get("priority", "normal"),
                "queue": parameters.get("queue") or config.get("default_queue"),
                "requester": parameters.get("requester"),
            },
            "correlation_id": correlation_id,
            "approval_request_id": approval_request_id,
        }
    if provider == "http":
        return {
            "agent_id": agent_id,
            "tool_name": tool_name,
            "parameters": parameters,
            "description": description,
            "correlation_id": correlation_id,
            "approval_request_id": approval_request_id,
        }
    raise DownstreamExecutionError(f"Unsupported executor integration provider '{provider}'")


async def execute_integrated_action(
    *,
    agent_id: str,
    tool_name: str,
    parameters: dict,
    description: str | None,
    correlation_id: str,
    approval_request_id: str | None,
    config: dict[str, Any],
) -> dict[str, Any]:
    provider = str(config.get("provider") or "http")
    url = _require_url(config, provider)
    payload = _build_provider_payload(
        provider=provider,
        agent_id=agent_id,
        tool_name=tool_name,
        parameters=parameters,
        description=description,
        correlation_id=correlation_id,
        approval_request_id=approval_request_id,
        config=config,
    )
    try:
        async with httpx.AsyncClient(timeout=settings.executor_timeout_seconds) as client:
            response = await client.post(
                url,
                json=payload,
                headers=_integration_headers(
                    config,
                    agent_id=agent_id,
                    tool_name=tool_name,
                    payload=payload,
                    correlation_id=correlation_id,
                    approval_request_id=approval_request_id,
                ),
            )
            response.raise_for_status()
            data = response.json()
            if not isinstance(data, dict):
                raise DownstreamExecutionError(
                    f"Executor integration '{provider}' returned a non-object response"
                )
            return {
                "status": data.get("status", "executed"),
                "provider": provider,
                "target_url": url,
                "result": data,
            }
    except httpx.HTTPStatusError as exc:
        raise DownstreamExecutionError(
            f"Executor integration '{provider}' returned HTTP {exc.response.status_code}"
        ) from exc
    except httpx.RequestError as exc:
        raise DownstreamExecutionError(
            f"Executor integration '{provider}' is unreachable: {exc}"
        ) from exc
