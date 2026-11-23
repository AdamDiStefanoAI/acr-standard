"""
Gateway router: POST /acr/evaluate — the main gateway endpoint.

Synchronous pipeline (<200ms budget):
  [1] Kill switch — direct Redis read
  [2] Identity check — validate agent exists and is active
  [3] Rate limit — server-side Redis counter (overrides self-reported context)
  [4] Policy evaluation — OPA allow/deny/escalate
  [5] Output filter — PII redaction on parameters
  [6] Decision recording — every decision is assigned its §18 sequence
      position and durably recorded before the response is returned and
      before any approved action executes (§11/§18). If the decision cannot
      be recorded, the evaluation fails secure with a 503 deny.
  [7] (if escalate) Approval queue creation

Async background tasks (non-blocking):
  [8] Telemetry persistence (observability copy; the policy decision
      records written in [6] are the durable evidence of the decision)
  [9] Drift metric sample recording
  [10] Drift score computation + graduated response check
"""

from __future__ import annotations

import time
from datetime import UTC, datetime

import structlog
from fastapi import APIRouter, BackgroundTasks, Depends
from fastapi.responses import JSONResponse
from sqlalchemy import update
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.ext.asyncio import AsyncSession

from acr.common.correlation import get_correlation_id
from acr.common.errors import (
    ACRError,
    AgentKilledError,
    AgentNotRegisteredError,
    PolicyEngineError,
    RuntimeControlDependencyError,
)
from acr.common.operator_auth import reject_auditor_operator_key
from acr.common.redis_client import get_redis_or_none
from acr.common.time import iso_utcnow
from acr.config import runtime_dependencies_fail_closed, settings
from acr.db.database import BackgroundSessionLocal, get_db
from acr.db.models import DecisionSequenceRecord, EvaluationInputRecord, PolicyDecisionRecord
from acr.gateway.auth import require_agent_token
from acr.gateway.executor import execute_action
from acr.gateway.models import EvaluateRequest, EvaluateResponse
from acr.gateway.spend_control import (
    adjust_authoritative_spend,
    get_authoritative_projected_spend,
    resolve_action_cost_usd,
)
from acr.pillar1_identity.registry import get_manifest
from acr.pillar1_identity.validator import validate_agent_identity
from acr.pillar2_policy.engine import canonical_tool_name, evaluate_policy
from acr.pillar2_policy.models import PolicyDecision
from acr.pillar2_policy.output_filter import ParameterFilterResult, filter_parameters
from acr.pillar3_drift.baseline import record_metric_sample
from acr.pillar4_observability.otel import acr_span, get_meter
from acr.pillar4_observability.schema import LatencyBreakdown, PolicyResult
from acr.pillar4_observability.telemetry import build_event, log_event, persist_event
from acr.pillar5_containment.graduated import _ISOLATE_PREFIX, _RESTRICT_PREFIX, _THROTTLE_PREFIX
from acr.pillar5_containment.killswitch import is_agent_killed
from acr.pillar6_authority import resumption
from acr.pillar6_authority.approval import create_approval_request

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/acr", tags=["Gateway"])

# Redis key prefix for server-side rate limit counters
_RATE_KEY_PREFIX = "acr:rate:"
# Redis key prefix for cached drift scores
_DRIFT_SCORE_PREFIX = "acr:drift:score:"
# Drift check cadence is settings.drift_check_every_n (default 1: every
# evaluation). The previous hard-coded every-10th-evaluation throttle let
# slow, sparse deviations accumulate below the sampling line.


# ── Background tasks ──────────────────────────────────────────────────────────


async def _record_drift_sample(
    agent_id: str,
    tool_name: str,
    policy_denied: bool,
    latency_ms: int,
    correlation_id: str,
) -> None:
    async with BackgroundSessionLocal() as db:
        try:
            await record_metric_sample(
                db,
                agent_id=agent_id,
                correlation_id=correlation_id,
                tool_name=tool_name,
                action_type=tool_name,
                policy_denied=policy_denied,
                latency_ms=latency_ms,
            )
            await db.commit()
        except Exception as exc:
            await db.rollback()
            logger.error("Background drift sample failed", error=str(exc), exc_info=True)


async def _run_drift_check(agent_id: str) -> None:
    """Compute drift score and apply graduated response. Caches result to Redis."""
    from acr.pillar3_drift.detector import run_drift_check

    async with BackgroundSessionLocal() as db:
        try:
            drift = await run_drift_check(db, agent_id)
            await db.commit()
            # Cache drift score for fast reads in subsequent responses
            redis = get_redis_or_none()
            if redis and drift.is_baseline_ready:
                await redis.setex(
                    f"{_DRIFT_SCORE_PREFIX}{agent_id}",
                    300,  # 5-minute TTL
                    str(drift.score),
                )
        except Exception as exc:
            await db.rollback()
            logger.error("Background drift check failed", error=str(exc), exc_info=True)


async def _persist_telemetry(event_dict: dict) -> None:
    from acr.pillar4_observability.schema import ACRTelemetryEvent

    async with BackgroundSessionLocal() as db:
        try:
            event = ACRTelemetryEvent.model_validate(event_dict)
            await persist_event(db, event)
            await db.commit()
        except Exception as exc:
            await db.rollback()
            logger.error("Background telemetry persist failed", error=str(exc), exc_info=True)


async def _assign_decision_sequence(db: AsyncSession, agent_id: str) -> int:
    """Atomically advance and return the agent's §18 decision sequence.

    The increment runs inside the transaction that records the decisions, so
    a decision's sequence position is fixed when the decision is issued and
    commits (or rolls back) together with the decision records themselves.
    """
    stmt = (
        update(DecisionSequenceRecord)
        .where(DecisionSequenceRecord.agent_id == agent_id)
        .values(last_sequence=DecisionSequenceRecord.last_sequence + 1)
        .returning(DecisionSequenceRecord.last_sequence)
    )
    value = (await db.execute(stmt)).scalar_one_or_none()
    if value is not None:
        return int(value)
    # First recorded decision for this agent: create the counter at 1. When
    # two first evaluations race, this insert can lose to the other
    # transaction's; _record_policy_decisions retries the whole recording
    # on that conflict, and the retry takes the UPDATE path above.
    db.add(DecisionSequenceRecord(agent_id=agent_id, last_sequence=1))
    await db.flush()
    return 1


async def _record_policy_decisions(
    db: AsyncSession,
    *,
    agent_id: str,
    correlation_id: str,
    tool_name: str,
    decisions: list[dict],
    enforcement_mode: str = "enforce",
    retained_input_data: dict | None = None,
) -> int:
    """Durably record one evaluation's policy decisions before responding.

    Returns the §18 decision sequence assigned at issuance. Raises on any
    persistence failure; the caller fails secure (§11: an action whose
    decision cannot be durably recorded must not proceed).

    Transient transaction conflicts (two first evaluations racing to create
    the agent's sequence counter, serialization failures under concurrency)
    are retried a bounded number of times before giving up.
    """
    last_exc: Exception | None = None
    for _attempt in range(3):
        try:
            sequence = await _assign_decision_sequence(db, agent_id)
            for item in decisions:
                db.add(
                    PolicyDecisionRecord(
                        correlation_id=correlation_id,
                        agent_id=agent_id,
                        policy_id=str(item["policy_id"]),
                        decision=str(item["decision"]),
                        enforcement_mode=enforcement_mode,
                        reason=item.get("reason"),
                        tool_name=tool_name,
                        latency_ms=item.get("latency_ms"),
                        sequence=sequence,
                    )
                )
            # WS2 input retention rides this transaction when the caller
            # supplies it: the retained input commits (or rolls back) with
            # the decisions it belongs to, so a retention write failure is
            # a recording failure and takes the same fail-secure path.
            if retained_input_data is not None:
                db.add(EvaluationInputRecord(**retained_input_data))
            await db.commit()
            return sequence
        except (IntegrityError, OperationalError) as exc:
            await db.rollback()
            last_exc = exc
    assert last_exc is not None
    raise last_exc


# ── Helpers ───────────────────────────────────────────────────────────────────


async def _get_rate_count(agent_id: str) -> int:
    """Increment and return the server-side action counter for this agent/minute."""
    redis = get_redis_or_none()
    if redis is None:
        if runtime_dependencies_fail_closed():
            raise RuntimeControlDependencyError(
                "Authoritative rate-limit counter unavailable: Redis is not initialized"
            )
        return 0
    now = datetime.now(UTC)
    minute_bucket = now.strftime("%Y%m%d%H%M")
    key = f"{_RATE_KEY_PREFIX}{agent_id}:{minute_bucket}"
    try:
        count = await redis.incr(key)
        await redis.expire(key, 120)  # expire after 2 minutes
        return count
    except Exception as exc:
        if runtime_dependencies_fail_closed():
            raise RuntimeControlDependencyError(
                f"Authoritative rate-limit counter unavailable: {exc}"
            ) from exc
        return 0


def _resolve_action_cost_usd(manifest, tool_name: str) -> float:
    return resolve_action_cost_usd(manifest, tool_name)


async def _get_authoritative_projected_spend(
    agent_id: str, estimated_action_cost_usd: float
) -> float:
    return await get_authoritative_projected_spend(agent_id, estimated_action_cost_usd)


async def _adjust_authoritative_spend(agent_id: str, delta_usd: float) -> None:
    await adjust_authoritative_spend(agent_id, delta_usd)


def _filter_reason(filter_result: ParameterFilterResult) -> str | None:
    if not filter_result.was_modified:
        return None
    redacted = ", ".join(filter_result.redacted_types)
    return f"Sensitive fields were redacted by output controls ({redacted})"


async def _get_cached_drift_score(agent_id: str) -> float | None:
    redis = get_redis_or_none()
    if redis is None:
        return None
    try:
        val = await redis.get(f"{_DRIFT_SCORE_PREFIX}{agent_id}")
        return float(val) if val else None
    except Exception:
        return None


async def _should_run_drift_check(agent_id: str) -> bool:
    """Return True every N-th call, per settings.drift_check_every_n.

    The counter only throttles a background detection job; it is not a
    control. When Redis is unavailable the check runs rather than silently
    never running.
    """
    every_n = max(1, settings.drift_check_every_n)
    if every_n == 1:
        return True
    redis = get_redis_or_none()
    if redis is None:
        return True
    key = f"acr:drift:counter:{agent_id}"
    try:
        n = await redis.incr(key)
        await redis.expire(key, 3600)
        return (n % every_n) == 0
    except Exception:
        return True


# ── Main endpoint ─────────────────────────────────────────────────────────────


@router.post("/evaluate", response_model=EvaluateResponse)
async def evaluate(
    req: EvaluateRequest,
    background_tasks: BackgroundTasks,
    # An auditor credential presented to the write path is rejected as an
    # auditor (403) before agent-token handling: auditor access is
    # read-only everywhere, including routes that do not use operator
    # auth (v1.5.0 WS3).
    _auditor_guard: None = Depends(reject_auditor_operator_key),
    authorized_agent_id: str = Depends(require_agent_token),
    db: AsyncSession = Depends(get_db),
) -> JSONResponse:
    """
    ACR Gateway — the central control plane decision point.
    All agent action requests flow through here.

    Requires a valid Bearer JWT issued by POST /acr/agents/{id}/token.
    The JWT's `sub` claim must match the `agent_id` in the request body.
    """
    correlation_id = get_correlation_id()
    start_time = iso_utcnow()
    t_start = time.monotonic()
    identity_ms = policy_ms = 0

    try:
        # ── [0] Token / body agent_id consistency check ───────────────────────
        # Prevents one agent from submitting actions on behalf of another.
        if authorized_agent_id != req.agent_id:
            return JSONResponse(
                status_code=403,
                content={
                    "decision": "deny",
                    "error_code": "AGENT_ID_MISMATCH",
                    "reason": "Token subject does not match request agent_id",
                },
            )

        # ── [1] Kill switch check (Redis direct read, ~0.5ms) ─────────────────
        if await is_agent_killed(req.agent_id):
            raise AgentKilledError(f"Agent '{req.agent_id}' is killed")

        # ── [1b] Graduated containment enforcement (Redis reads) ─────────────
        # These keys are written by the drift-scoring background worker in
        # graduated.py when an agent's drift score crosses a tier threshold.
        # Containment state is a control input: when it cannot be read, the
        # evaluation fails closed rather than proceeding uncontained.
        # Containment (and the kill switch above) is EXEMPT from observe
        # mode: these checks run before the agent's enforcement mode is
        # read and return on their own, so an observe-mode agent under
        # restrict/isolate/kill is contained exactly as an enforcing one.
        redis = get_redis_or_none()
        if redis is None and runtime_dependencies_fail_closed():
            raise RuntimeControlDependencyError(
                "Graduated containment state unavailable: Redis is not initialized"
            )
        if redis is not None:
            # Tier 3 — Isolate: override every decision to escalate
            isolate_val = await redis.get(f"{_ISOLATE_PREFIX}{req.agent_id}")
            if isolate_val == "1":
                return JSONResponse(
                    status_code=202,
                    content={
                        "decision": "escalate",
                        "correlation_id": correlation_id,
                        "reason": "agent_isolated_all_actions_require_approval",
                    },
                )

            # Tier 2 — Restrict: only whitelisted tools are allowed
            restrict_val = await redis.get(f"{_RESTRICT_PREFIX}{req.agent_id}")
            if restrict_val is not None:
                import json as _json

                allowed_tools = _json.loads(restrict_val)
                canonical_allowed = [canonical_tool_name(t) for t in allowed_tools]
                if canonical_tool_name(req.action.tool_name) not in canonical_allowed:
                    return JSONResponse(
                        status_code=403,
                        content={
                            "decision": "deny",
                            "correlation_id": correlation_id,
                            "reason": "agent_restricted_tool_not_allowed",
                        },
                    )

            # Tier 1 — Throttle: reduce effective rate limit by the throttle %
            throttle_val = await redis.get(f"{_THROTTLE_PREFIX}{req.agent_id}")
            if throttle_val is not None:
                throttle_pct = int(throttle_val)
                # We apply the throttle in step [3] by scaling the effective limit.
                # Store for later use.
                enriched_context_throttle_pct = throttle_pct
            else:
                enriched_context_throttle_pct = 100
        else:
            enriched_context_throttle_pct = 100

        # ── [2] Identity check ────────────────────────────────────────────────
        with acr_span("identity_check", {"agent.id": req.agent_id}):
            t0 = time.monotonic()
            await validate_agent_identity(db, req.agent_id)
            manifest = await get_manifest(db, req.agent_id)
            identity_ms = int((time.monotonic() - t0) * 1000)

        # Enforcement mode (v1.5.0 WS1) comes ONLY from the stored agent
        # record, via the manifest. Nothing in the request — headers, body
        # fields, context, parameters, tool names — can influence it; there
        # is deliberately no code path that reads a mode from `req`. The
        # only write paths are registration and the operator-only
        # enforcement-mode transition endpoint.
        enforcement_mode = manifest.enforcement_mode
        observe = enforcement_mode == "observe"

        # ── [3] Server-side rate limit counter ────────────────────────────────
        # Override self-reported count with the authoritative server-side value.
        # When Tier 1 (throttle) is active the effective count is scaled up so
        # the agent hits its limit sooner (e.g. 50% throttle → count * 2).
        server_count = await _get_rate_count(req.agent_id)
        if enriched_context_throttle_pct < 100:
            effective_count = int(server_count * (100 / enriched_context_throttle_pct))
        else:
            effective_count = server_count

        estimated_action_cost_usd = _resolve_action_cost_usd(manifest, req.action.tool_name)
        projected_hourly_spend_usd = await _get_authoritative_projected_spend(
            req.agent_id,
            estimated_action_cost_usd,
        )
        enriched_context = {
            **req.context,
            "actions_this_minute": effective_count,
            "hourly_spend_usd": projected_hourly_spend_usd,
        }

        # ── [4] Policy evaluation (OPA) ───────────────────────────────────────
        with acr_span(
            "policy_evaluation", {"agent.id": req.agent_id, "action.tool": req.action.tool_name}
        ):
            t0 = time.monotonic()
            policy_result = await evaluate_policy(
                agent_manifest=manifest.model_dump(),
                action=req.action.model_dump(),
                context=enriched_context,
            )
            policy_ms = int((time.monotonic() - t0) * 1000)

        # ── [5] Output filter — PII redaction ─────────────────────────────────
        effective_action = req.action.model_dump()
        if policy_result.final_decision == "modify":
            if policy_result.modified_action is not None:
                candidate_tool_name = policy_result.modified_action.get(
                    "tool_name", req.action.tool_name
                )
                if candidate_tool_name != req.action.tool_name:
                    return JSONResponse(
                        status_code=403,
                        content={
                            "decision": "deny",
                            "correlation_id": correlation_id,
                            "reason": "Runtime policy attempted to modify the action tool_name",
                            "error_code": "INVALID_MODIFY_DECISION",
                        },
                    )
                effective_action.update(policy_result.modified_action)
                effective_action.setdefault("description", req.action.description)
            elif policy_result.modified_parameters is not None:
                effective_action["parameters"] = policy_result.modified_parameters

        filter_result = filter_parameters(
            effective_action["tool_name"],
            effective_action.get("parameters") or {},
            correlation_id,
        )
        effective_action["parameters"] = filter_result.parameters

        response_decision = policy_result.final_decision
        response_reason = policy_result.reason
        response_decisions = list(policy_result.decisions)
        if response_decision == "allow" and filter_result.was_modified:
            response_decision = "modify"
            response_reason = _filter_reason(filter_result)
            response_decisions.append(
                PolicyDecision(
                    policy_id="acr-output-modify",
                    decision="modify",
                    reason=response_reason,
                    latency_ms=0,
                )
            )
        elif response_decision == "modify" and not response_reason:
            response_reason = (
                _filter_reason(filter_result) or "Action transformed by runtime policy"
            )

        total_ms = int((time.monotonic() - t_start) * 1000)
        end_time = iso_utcnow()

        telemetry_policies = [
            PolicyResult(
                policy_id=d.policy_id,
                decision=d.decision,  # type: ignore[arg-type]
                reason=d.reason,
                latency_ms=d.latency_ms,
            )
            for d in response_decisions
        ]

        # Fetch cached drift score for inclusion in response
        drift_score = await _get_cached_drift_score(req.agent_id)

        # Record OTEL metrics for all decisions
        _record_evaluate_metrics(req.agent_id, response_decision, total_ms)

        # ── [6] Durable decision recording (§11/§18) ──────────────────────────
        # The decision is assigned its sequence position and committed before
        # the response is returned and before any approved action executes.
        # A crash after this point cannot lose the decision, and the sequence
        # reflects issuance order, not persistence or completion order. If
        # recording fails, the evaluation fails secure: an unrecorded
        # decision is not evidence of enforcement.
        #
        # WS2: when the deployment has opted in to evaluation-input
        # retention, the effective evaluation input (the exact manifest,
        # action, and enriched context handed to the policy engine at step
        # [4], redacted before storage) is written inside the same
        # recording transaction. Retention off (the default) passes None
        # and this step is byte-for-byte the pre-WS2 behavior.
        retained_input_data = None
        if settings.evaluation_input_retention_enabled:
            from acr.pillar4_observability.input_retention import build_retained_input_data

            retained_input_data = build_retained_input_data(
                correlation_id=correlation_id,
                agent_id=req.agent_id,
                evaluation_input={
                    "agent": manifest.model_dump(mode="json"),
                    "action": req.action.model_dump(mode="json"),
                    "context": enriched_context,
                },
                recorded_decision=response_decision,
                enforcement_mode=enforcement_mode,
            )
        try:
            decision_sequence = await _record_policy_decisions(
                db,
                agent_id=req.agent_id,
                correlation_id=correlation_id,
                tool_name=effective_action["tool_name"],
                decisions=[d.model_dump(mode="json") for d in response_decisions],
                enforcement_mode=enforcement_mode,
                retained_input_data=retained_input_data,
            )
        except Exception as exc:
            await db.rollback()
            logger.error(
                "Policy decision recording failed",
                agent_id=req.agent_id,
                correlation_id=correlation_id,
                error=str(exc),
                exc_info=True,
            )
            return JSONResponse(
                status_code=503,
                content={
                    "decision": "deny",
                    "correlation_id": correlation_id,
                    "reason": "Decision could not be durably recorded; failing secure",
                    "error_code": "EVIDENCE_PERSISTENCE_FAILED",
                },
            )

        # ── [6b] Sentinel export enqueue (v1.5.0 WS4) ───────────────────────
        # Strictly after the recording commit above, in its own guarded
        # transaction: the export is a copy of the recorded evidence, never
        # part of it. Any failure is logged and swallowed — it cannot
        # delay (beyond one local insert), block, or alter the decision.
        if settings.sentinel_enabled:
            try:
                from acr.integrations.events import enqueue_sentinel_decisions

                await enqueue_sentinel_decisions(
                    db, correlation_id=correlation_id, sequence=decision_sequence
                )
                await db.commit()
            except Exception as exc:  # export must never touch enforcement
                await db.rollback()
                logger.warning(
                    "sentinel_export_enqueue_failed",
                    correlation_id=correlation_id,
                    error=str(exc),
                )

        # ── [7] Escalate → approval queue ─────────────────────────────────────
        # Enforce mode only: in observe mode a would-be escalation is
        # recorded (step [6]) and the call proceeds via step [9] — no
        # approval request is created for a call nobody is gating.
        if response_decision == "escalate" and not observe:
            authorization_snapshot = None
            if policy_result.policy_identity is not None:
                expected = await resumption.expected_policy_identity(db)
                if expected != policy_result.policy_identity:
                    raise PolicyEngineError("Evaluator has not loaded the active approval policy")
                authorization_snapshot = resumption.authorization_snapshot(
                    manifest, expected, await resumption.containment(req.agent_id)
                )
            approval = await create_approval_request(
                db,
                correlation_id=correlation_id,
                agent_id=req.agent_id,
                tool_name=effective_action["tool_name"],
                parameters=effective_action["parameters"],
                description=effective_action.get("description"),
                authorization_snapshot=authorization_snapshot,
                request_context=req.context,
                approval_queue=policy_result.approval_queue or "default",
                sla_minutes=policy_result.sla_minutes or 240,
            )
            # Make the approval request visible before returning its request_id.
            await db.commit()
            await db.refresh(approval)
            _queue_background_tasks(
                background_tasks,
                agent_id=req.agent_id,
                tool_name=req.action.tool_name,
                policy_denied=False,
                total_ms=total_ms,
                correlation_id=correlation_id,
                event_kwargs={
                    "event_type": "ai_inference",
                    "manifest": manifest,
                    "correlation_id": correlation_id,
                    "req": req,
                    "filtered_params": effective_action["parameters"],
                    "start_time": start_time,
                    "end_time": end_time,
                    "total_ms": total_ms,
                    "identity_ms": identity_ms,
                    "policy_ms": policy_ms,
                    "telemetry_policies": telemetry_policies,
                    "output_decision": "escalate",
                    "output_reason": response_reason,
                    "enforcement_mode": enforcement_mode,
                    "approval_request_id": approval.request_id,
                    "drift_score": drift_score,
                    "output_filtered": filter_result.was_modified,
                    "filter_reason": _filter_reason(filter_result),
                    "modified_parameters": effective_action["parameters"]
                    if response_decision == "modify"
                    else None,
                    "tool_name": effective_action["tool_name"],
                    "description": effective_action.get("description"),
                    "custom": {
                        "estimated_cost_usd": estimated_action_cost_usd,
                        "authoritative_hourly_spend_usd": projected_hourly_spend_usd,
                        "cost_basis": "authorization_estimate",
                        "decision_sequence": decision_sequence,
                    },
                },
            )
            return JSONResponse(
                status_code=202,
                content={
                    "decision": "escalate",
                    "correlation_id": correlation_id,
                    "enforcement_mode": enforcement_mode,
                    "enforced": True,
                    "approval_request_id": approval.request_id,
                    "reason": response_reason,
                    "approval_queue": approval.approval_queue,
                    "sla_minutes": approval.sla_minutes,
                },
            )

        # ── [8] Deny ──────────────────────────────────────────────────────────
        # Enforce mode only: an observe-mode would-be deny proceeds via [9].
        if response_decision == "deny" and not observe:
            _queue_background_tasks(
                background_tasks,
                agent_id=req.agent_id,
                tool_name=effective_action["tool_name"],
                policy_denied=True,
                total_ms=total_ms,
                correlation_id=correlation_id,
                event_kwargs={
                    "event_type": "policy_decision",
                    "manifest": manifest,
                    "correlation_id": correlation_id,
                    "req": req,
                    "filtered_params": effective_action["parameters"],
                    "start_time": start_time,
                    "end_time": end_time,
                    "total_ms": total_ms,
                    "identity_ms": identity_ms,
                    "policy_ms": policy_ms,
                    "telemetry_policies": telemetry_policies,
                    "output_decision": "deny",
                    "output_reason": response_reason,
                    "enforcement_mode": enforcement_mode,
                    "approval_request_id": None,
                    "drift_score": drift_score,
                    "output_filtered": filter_result.was_modified,
                    "filter_reason": _filter_reason(filter_result),
                    "modified_parameters": effective_action["parameters"]
                    if response_decision == "modify"
                    else None,
                    "tool_name": effective_action["tool_name"],
                    "description": effective_action.get("description"),
                    "custom": {
                        "estimated_cost_usd": estimated_action_cost_usd,
                        "authoritative_hourly_spend_usd": projected_hourly_spend_usd,
                        "cost_basis": "authorization_estimate",
                        "decision_sequence": decision_sequence,
                    },
                },
            )
            return JSONResponse(
                status_code=403,
                content={
                    "decision": "deny",
                    "correlation_id": correlation_id,
                    "enforcement_mode": enforcement_mode,
                    "enforced": True,
                    "reason": response_reason,
                    "policy_decisions": [
                        {"policy_id": d.policy_id, "decision": d.decision, "reason": d.reason}
                        for d in response_decisions
                    ],
                },
            )

        # ── [9] Allow / Modify — and, in observe mode, every outcome ─────────
        # Observe mode reaches this block for ALL would-be outcomes: the
        # decision was recorded at step [6] with the same §18 semantics as
        # an enforced one, and the call now proceeds. Arriving here does
        # NOT bypass containment or the kill switch — those run at steps
        # [1]/[1b], before mode is read, and return on their own.
        #
        # What runs in observe mode is the agent's requested action. A
        # policy "modify" verdict must not silently change behavior while
        # merely observing, so for a would-be modify the requested action
        # proceeds with only the standing output-filter redaction applied
        # to its parameters (the filter is a data control, not enforcement,
        # and applies in both modes).
        run_tool_name = effective_action["tool_name"]
        run_parameters = effective_action["parameters"]
        run_description = effective_action.get("description")
        if observe and policy_result.final_decision == "modify":
            requested_filter = filter_parameters(
                req.action.tool_name,
                req.action.parameters or {},
                correlation_id,
            )
            run_tool_name = req.action.tool_name
            run_parameters = requested_filter.parameters
            run_description = req.action.description

        execution_result = None
        if settings.execute_allowed_actions:
            await _adjust_authoritative_spend(req.agent_id, estimated_action_cost_usd)
            try:
                execution_result = await execute_action(
                    agent_id=req.agent_id,
                    tool_name=run_tool_name,
                    parameters=run_parameters,
                    description=run_description,
                    correlation_id=correlation_id,
                )
            except Exception:
                await _adjust_authoritative_spend(req.agent_id, -estimated_action_cost_usd)
                raise
        else:
            await _adjust_authoritative_spend(req.agent_id, estimated_action_cost_usd)
        _queue_background_tasks(
            background_tasks,
            agent_id=req.agent_id,
            tool_name=run_tool_name,
            policy_denied=response_decision == "deny",
            total_ms=total_ms,
            correlation_id=correlation_id,
            event_kwargs={
                "event_type": "policy_decision" if response_decision == "deny" else "ai_inference",
                "manifest": manifest,
                "correlation_id": correlation_id,
                "req": req,
                "filtered_params": run_parameters,
                "start_time": start_time,
                "end_time": end_time,
                "total_ms": total_ms,
                "identity_ms": identity_ms,
                "policy_ms": policy_ms,
                "telemetry_policies": telemetry_policies,
                "output_decision": response_decision,
                "output_reason": response_reason,
                "enforcement_mode": enforcement_mode,
                "approval_request_id": None,
                "drift_score": drift_score,
                "output_filtered": filter_result.was_modified,
                "filter_reason": _filter_reason(filter_result),
                "modified_parameters": effective_action["parameters"]
                if response_decision == "modify" and not observe
                else None,
                "tool_name": run_tool_name,
                "description": run_description,
                "custom": {
                    "estimated_cost_usd": estimated_action_cost_usd,
                    "authoritative_hourly_spend_usd": projected_hourly_spend_usd,
                    "cost_basis": "authorization_estimate",
                    "decision_sequence": decision_sequence,
                },
            },
        )
        if observe:
            # Non-blocking by construction: HTTP 200 and decision "allow"
            # (the effective outcome), with the would-be decision carried
            # explicitly so callers and the SDK can log what enforcement
            # would have done. No approval is created and no modified
            # action is substituted.
            content = {
                "decision": "allow",
                "correlation_id": correlation_id,
                "enforcement_mode": "observe",
                "would_be_decision": response_decision,
                "enforced": False,
                "policy_decisions": [
                    {"policy_id": d.policy_id, "decision": d.decision, "reason": d.reason}
                    for d in response_decisions
                ],
                "drift_score": drift_score,
                "latency_ms": total_ms,
                "estimated_cost_usd": estimated_action_cost_usd,
                "authoritative_hourly_spend_usd": projected_hourly_spend_usd,
            }
            if response_reason:
                content["reason"] = response_reason
            if execution_result is not None:
                content["execution_result"] = execution_result
            return JSONResponse(status_code=200, content=content)
        content = {
            "decision": response_decision,
            "correlation_id": correlation_id,
            "enforcement_mode": enforcement_mode,
            "enforced": True,
            "policy_decisions": [
                {"policy_id": d.policy_id, "decision": d.decision, "reason": d.reason}
                for d in response_decisions
            ],
            "drift_score": drift_score,
            "latency_ms": total_ms,
            "estimated_cost_usd": estimated_action_cost_usd,
            "authoritative_hourly_spend_usd": projected_hourly_spend_usd,
        }
        if response_reason:
            content["reason"] = response_reason
        if response_decision == "modify":
            content["modified_action"] = {
                "tool_name": effective_action["tool_name"],
                "parameters": effective_action["parameters"],
                "description": effective_action.get("description"),
            }
        if execution_result is not None:
            content["execution_result"] = execution_result
        return JSONResponse(status_code=200, content=content)

    except AgentKilledError as exc:
        return JSONResponse(
            status_code=403,
            content={"decision": "deny", "reason": exc.message, "error_code": exc.error_code},
        )
    except AgentNotRegisteredError as exc:
        return JSONResponse(
            status_code=403,
            content={"decision": "deny", "reason": exc.message, "error_code": exc.error_code},
        )
    except PolicyEngineError as exc:
        # Fail-secure: OPA down → deny
        return JSONResponse(
            status_code=503,
            content={
                "decision": "deny",
                "reason": f"Policy engine unavailable: {exc.message}",
                "error_code": exc.error_code,
            },
        )
    except ACRError as exc:
        return JSONResponse(
            status_code=exc.status_code,
            content={"decision": "deny", "reason": exc.message, "error_code": exc.error_code},
        )
    except Exception:
        # Fail-secure: never expose stack traces to clients
        return JSONResponse(
            status_code=500,
            content={
                "decision": "deny",
                "reason": "Internal control plane error",
                "error_code": "INTERNAL_ERROR",
            },
        )


# ── OTEL metrics helper ──────────────────────────────────────────────────────


def _record_evaluate_metrics(agent_id: str, decision: str, latency_ms: int) -> None:
    """Increment OTLP counters/histograms for each evaluate call."""
    meter = get_meter()
    meter.create_counter("acr.evaluate.total").add(1, {"agent_id": agent_id, "decision": decision})
    meter.create_histogram("acr.evaluate.latency", unit="ms").record(
        latency_ms, {"agent_id": agent_id}
    )


# ── Background task helpers ───────────────────────────────────────────────────


def _queue_background_tasks(
    background_tasks: BackgroundTasks,
    *,
    agent_id: str,
    tool_name: str,
    policy_denied: bool,
    total_ms: int,
    correlation_id: str,
    event_kwargs: dict,
) -> None:
    """Queue all post-response background work."""
    background_tasks.add_task(
        _emit_telemetry_event,
        **event_kwargs,
    )
    background_tasks.add_task(
        _record_drift_sample,
        agent_id,
        tool_name,
        policy_denied,
        total_ms,
        correlation_id,
    )
    background_tasks.add_task(_maybe_run_drift_check, agent_id)


async def _maybe_run_drift_check(agent_id: str) -> None:
    """Run drift check only every N evaluations to avoid hammering the DB."""
    if await _should_run_drift_check(agent_id):
        await _run_drift_check(agent_id)


async def _emit_telemetry_event(
    *,
    event_type,
    manifest,
    correlation_id,
    req,
    filtered_params,
    start_time,
    end_time,
    total_ms,
    identity_ms,
    policy_ms,
    telemetry_policies,
    output_decision,
    output_reason,
    approval_request_id,
    drift_score,
    enforcement_mode="enforce",
    output_filtered=False,
    filter_reason=None,
    modified_parameters=None,
    custom=None,
    tool_name=None,
    description=None,
) -> None:
    event = build_event(
        event_type=event_type,
        agent_id=manifest.agent_id,
        agent_purpose=manifest.purpose,
        agent_capabilities=manifest.allowed_tools,
        correlation_id=correlation_id,
        session_id=req.context.get("session_id"),
        tool_name=tool_name or req.action.tool_name,
        parameters=filtered_params,
        description=description if description is not None else req.action.description,
        context=req.context,
        intent=req.intent.model_dump(exclude_none=True) if req.intent else {},
        start_time=start_time,
        end_time=end_time,
        duration_ms=total_ms,
        latency_breakdown=LatencyBreakdown(
            identity_ms=identity_ms, policy_ms=policy_ms, total_ms=total_ms
        ),
        policies=telemetry_policies,
        output_decision=output_decision,
        output_reason=output_reason,
        enforcement_mode=enforcement_mode,
        approval_request_id=approval_request_id,
        drift_score=drift_score,
        output_filtered=output_filtered,
        filter_reason=filter_reason,
        modified_parameters=modified_parameters,
        custom=custom,
    )
    log_event(event)
    await _persist_telemetry(event.model_dump(mode="json"))
