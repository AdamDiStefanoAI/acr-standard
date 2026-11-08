"""Pillar 2: OPA policy engine client with circuit breaker."""

from __future__ import annotations

import asyncio
import time
from datetime import timedelta
from typing import Any

import httpx
import structlog
from aiobreaker import CircuitBreaker, CircuitBreakerError

from acr.common.errors import PolicyEngineError
from acr.config import settings
from acr.pillar2_policy.models import PolicyDecision, PolicyEvaluationResult
from acr.policy_studio.core_bundle import core_identity, operator_identity

logger = structlog.get_logger(__name__)

# Separate connect / read timeouts; keeps hot-path latency predictable.
_TIMEOUT = httpx.Timeout(timeout=3.0, connect=2.0)

# Retry config: up to 3 attempts with exponential back-off.
# Only retried on transient network/5xx errors, never on 4xx.
_MAX_RETRIES = 3
_RETRY_BASE_DELAY = 0.05  # seconds; doubles each attempt → 50ms, 100ms, 200ms

# HTTP status codes that are worth retrying (transient server-side failures)
_RETRYABLE_STATUS = {429, 500, 502, 503, 504}

# Module-level connection-pooled client (avoids creating a new TCP connection per call)
_opa_client: httpx.AsyncClient | None = None
_opa_client_factory: object | None = None


def get_opa_client() -> httpx.AsyncClient:
    global _opa_client, _opa_client_factory
    current_factory = httpx.AsyncClient
    if _opa_client is None or _opa_client_factory is not current_factory:
        _opa_client = httpx.AsyncClient(base_url=settings.opa_url, timeout=_TIMEOUT)
        _opa_client_factory = current_factory
    return _opa_client


async def close_opa_client() -> None:
    global _opa_client, _opa_client_factory
    if _opa_client is not None:
        await _opa_client.aclose()
        _opa_client = None
        _opa_client_factory = None


# Circuit breaker: opens after 5 failures in 60 seconds, fails secure
opa_breaker = CircuitBreaker(fail_max=5, timeout_duration=timedelta(seconds=60))


async def _call_opa(opa_input: dict) -> dict:
    """Execute the OPA HTTP call with retry logic. Raises on all-retries-exhausted."""
    last_exc: Exception | None = None
    data: dict = {}

    for attempt in range(_MAX_RETRIES):
        try:
            client = get_opa_client()
            resp = await client.post("/v1/data/acr", json=opa_input)

            # Don't retry client errors (4xx) — they signal bad input, not OPA failure
            if 400 <= resp.status_code < 500 and resp.status_code not in _RETRYABLE_STATUS:
                resp.raise_for_status()

            if resp.status_code in _RETRYABLE_STATUS:
                raise httpx.HTTPStatusError(
                    f"OPA returned HTTP {resp.status_code}",
                    request=resp.request,
                    response=resp,
                )

            resp.raise_for_status()
            data = resp.json()
            return data

        except (httpx.RequestError, httpx.HTTPStatusError) as exc:
            last_exc = exc
            if attempt < _MAX_RETRIES - 1:
                delay = _RETRY_BASE_DELAY * (2**attempt)
                logger.warning(
                    "opa_retry",
                    attempt=attempt + 1,
                    delay_s=delay,
                    error=str(exc),
                )
                await asyncio.sleep(delay)

    # All retries exhausted — raise to trip the circuit breaker
    raise PolicyEngineError(
        f"OPA unreachable after {_MAX_RETRIES} attempts: {last_exc}"
    ) from last_exc


async def evaluate_policy(
    agent_manifest: dict,
    action: dict,
    context: dict,
) -> PolicyEvaluationResult:
    """
    Send action context to OPA and parse allow/deny/escalate decision.
    Targets <100ms at P95.

    Uses a circuit breaker: if OPA fails 5 times in 60s, the circuit opens
    and subsequent calls return deny immediately (fail-secure).
    """
    start_ms = time.monotonic()

    # Inject safe defaults so missing context keys never bypass policy checks.
    safe_context = {
        "actions_this_minute": 0,
        "hourly_spend_usd": 0.0,
        **context,  # caller's real values override the defaults
    }

    opa_input = {
        "input": {
            "agent": agent_manifest,
            "action": action,
            "context": safe_context,
        }
    }

    try:
        data = await opa_breaker.call_async(_call_opa, opa_input)
    except CircuitBreakerError:
        logger.warning("opa_circuit_open", msg="OPA circuit open — failing secure")
        elapsed_ms = int((time.monotonic() - start_ms) * 1000)
        return PolicyEvaluationResult(
            final_decision="deny",
            decisions=[
                PolicyDecision(
                    policy_id="acr-circuit-open",
                    decision="deny",
                    reason="OPA circuit breaker open — failing secure",
                    latency_ms=elapsed_ms,
                )
            ],
            reason="OPA circuit breaker open — failing secure",
            latency_ms=elapsed_ms,
        )
    except PolicyEngineError:
        raise

    elapsed_ms = int((time.monotonic() - start_ms) * 1000)

    # Defensive: treat missing/null `result` as empty (deny-by-default still applies)
    result = data.get("result") or {}

    # Check the identity returned in this exact OPA evaluation, not a prior
    # readiness probe. A stale/missing/mixed bundle must never authorize work.
    if not isinstance(result, dict) or result.get("core_identity") != core_identity():
        raise PolicyEngineError("Missing, stale, or incompatible managed core policy bundle")

    try:
        expected_operator = operator_identity(settings.policy_extension_dir or None)
    except (ValueError, OSError) as exc:
        raise PolicyEngineError("Invalid operator policy configuration") from exc
    if result.get("operator_identity") != expected_operator:
        raise PolicyEngineError("Missing or stale operator policy bundle")

    deny_reasons: list[str] = result.get("deny", [])
    allow: bool = result.get("allow", False)
    modify: bool = result.get("modify", False)
    escalate: bool = result.get("escalate", False)
    escalate_queue: str = result.get("escalate_queue", "default")
    escalate_sla: int = result.get("escalate_sla_minutes", 240)
    modified_action = _coerce_dict(result.get("modified_action"))
    modified_parameters = _coerce_dict(result.get("modified_parameters"))

    decisions: list[PolicyDecision] = []

    if deny_reasons:
        final = "deny"
        reason = "; ".join(deny_reasons)
        for i, r in enumerate(deny_reasons):
            decisions.append(
                PolicyDecision(
                    policy_id=f"acr-deny-{i}",
                    decision="deny",
                    reason=r,
                    latency_ms=elapsed_ms,
                )
            )
    elif escalate:
        final = "escalate"
        reason = f"Action requires human approval (queue: {escalate_queue})"
        decisions.append(
            PolicyDecision(
                policy_id="acr-escalate",
                decision="escalate",
                reason=reason,
                latency_ms=elapsed_ms,
            )
        )
    elif modify:
        modified_payload = modified_action or modified_parameters
        if modified_payload is None:
            final = "deny"
            reason = "Policy requested modify without supplying a transformed payload"
            decisions.append(
                PolicyDecision(
                    policy_id="acr-invalid-modify",
                    decision="deny",
                    reason=reason,
                    latency_ms=elapsed_ms,
                )
            )
        else:
            final = "modify"
            reason = "Action transformed by runtime policy"
            decisions.append(
                PolicyDecision(
                    policy_id="acr-modify",
                    decision="modify",
                    reason=reason,
                    latency_ms=elapsed_ms,
                )
            )
    elif allow:
        final = "allow"
        reason = None
        decisions.append(
            PolicyDecision(
                policy_id="acr-allow",
                decision="allow",
                latency_ms=elapsed_ms,
            )
        )
    else:
        # OPA returned neither allow=true nor deny=[...] — fail-secure: deny
        final = "deny"
        reason = "Policy did not explicitly allow this action (deny-by-default)"
        decisions.append(
            PolicyDecision(
                policy_id="acr-default-deny",
                decision="deny",
                reason=reason,
                latency_ms=elapsed_ms,
            )
        )

    logger.debug(
        "opa_evaluation",
        final=final,
        latency_ms=elapsed_ms,
        deny_reasons=deny_reasons,
        escalate=escalate,
    )

    return PolicyEvaluationResult(
        final_decision=final,  # type: ignore[arg-type]
        decisions=decisions,
        reason=reason,
        approval_queue=escalate_queue if escalate else None,
        sla_minutes=escalate_sla if escalate else None,
        modified_action=modified_action if final == "modify" else None,
        modified_parameters=modified_parameters if final == "modify" else None,
        latency_ms=elapsed_ms,
    )


def _coerce_dict(value: Any) -> dict[str, Any] | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        return None
    return value
