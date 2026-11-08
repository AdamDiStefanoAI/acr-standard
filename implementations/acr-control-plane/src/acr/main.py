"""
ACR Control Plane — FastAPI application entrypoint.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager, suppress
from datetime import UTC, datetime, timedelta

import httpx
import structlog
from fastapi import Depends, FastAPI, Request
from fastapi.openapi.docs import get_redoc_html, get_swagger_ui_html
from fastapi.responses import JSONResponse, PlainTextResponse, Response
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from acr.auth.router import router as auth_router  # noqa: E402
from acr.common.correlation import get_correlation_id
from acr.common.errors import ACRError
from acr.common.operator_auth import OperatorPrincipal, require_operator_roles
from acr.common.redis_client import close_redis, init_redis
from acr.common.time import iso_utcnow
from acr.config import assert_production_secrets, effective_schema_bootstrap_mode, settings
from acr.db.database import background_engine, engine, get_db
from acr.db.models import Base
from acr.gateway.middleware import CorrelationMiddleware
from acr.operator_console.router import router as console_router  # noqa: E402
from acr.operator_console.router import static_files as console_static_files  # noqa: E402
from acr.pillar4_observability.evidence import build_evidence_bundle
from acr.pillar4_observability.otel import setup_otel, setup_telemetry
from acr.pillar4_observability.schema import LatencyBreakdown
from acr.pillar4_observability.telemetry import build_event, persist_event

# ── Configure structlog ───────────────────────────────────────────────────────
structlog.configure(
    processors=[
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer(),
    ],
    logger_factory=structlog.PrintLoggerFactory(),
)

logging.basicConfig(level=getattr(logging, settings.log_level.upper(), logging.INFO))


# ── App lifespan ──────────────────────────────────────────────────────────────


async def _approval_expiry_loop() -> None:
    """Periodically expire timed-out approval requests (runs every 60 s)."""
    from acr.db.database import async_session_factory
    from acr.pillar6_authority.approval import expire_timed_out_approvals

    log = structlog.get_logger(__name__)
    while True:
        await asyncio.sleep(60)
        async with async_session_factory() as db:
            try:
                expired = await expire_timed_out_approvals(db)
                await db.commit()
                if expired:
                    log.info("approval_sla_expired", count=expired)
            except Exception as exc:
                await db.rollback()
                log.warning("approval_expiry_error", error=str(exc))


async def _heartbeat_sweep_loop() -> None:
    """Periodically downgrade agents whose heartbeats have gone stale."""
    from acr.db.database import async_session_factory
    from acr.pillar1_identity.registry import sweep_stale_heartbeats

    log = structlog.get_logger(__name__)
    interval = max(1, settings.agent_heartbeat_sweep_interval_seconds)
    threshold = settings.agent_heartbeat_stale_seconds
    if threshold <= 0:
        log.info("heartbeat_sweep_disabled")
        return
    while True:
        await asyncio.sleep(interval)
        async with async_session_factory() as db:
            try:
                downgraded = await sweep_stale_heartbeats(db, threshold_seconds=threshold)
                await db.commit()
                if downgraded:
                    log.info("heartbeat_sweep_downgraded", count=downgraded)
            except Exception as exc:
                await db.rollback()
                log.warning("heartbeat_sweep_error", error=str(exc))


async def _retention_loop() -> None:
    """Periodically drop partitions / delete rows older than 90 days (runs daily)."""
    from acr.db.database import async_session_factory as _retention_session_factory

    log = structlog.get_logger(__name__)
    while True:
        await asyncio.sleep(86400)  # daily
        cutoff = datetime.now(UTC) - timedelta(days=90)
        try:
            async with _retention_session_factory() as db:
                await db.execute(
                    text("DELETE FROM telemetry_events WHERE created_at < :cutoff"),
                    {"cutoff": cutoff},
                )
                await db.execute(
                    text("DELETE FROM drift_metrics WHERE created_at < :cutoff"),
                    {"cutoff": cutoff},
                )
                await db.commit()
            log.info("retention_sweep_complete", cutoff=cutoff.isoformat())
        except Exception as exc:
            log.warning("retention_sweep_error", error=str(exc))


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    # Startup: reject weak secrets in staging/production environments
    assert_production_secrets()

    # Startup: initialise OpenTelemetry
    setup_otel()
    setup_telemetry(app, engine)

    # Startup: initialise Redis connection pool
    try:
        await init_redis()
    except Exception:
        if settings.strict_dependency_startup or settings.acr_env not in ("development", "test"):
            raise
        structlog.get_logger(__name__).warning("redis_init_failed_continuing_without_redis")

    # Startup: manage schema according to environment policy.
    mode = effective_schema_bootstrap_mode()
    async with engine.begin() as conn:
        if mode == "create":
            await conn.run_sync(Base.metadata.create_all)
        elif mode == "validate":
            required_tables = {
                "agents",
                "approval_requests",
                "telemetry_events",
                "drift_metrics",
                "drift_baseline_versions",
                "operator_credentials",
                "policy_drafts",
            }

            def _missing_tables(sync_conn):
                from sqlalchemy import inspect

                inspector = inspect(sync_conn)
                existing = set(inspector.get_table_names())
                return sorted(required_tables - existing)

            missing = await conn.run_sync(_missing_tables)
            if missing:
                raise RuntimeError(
                    "Database schema is incomplete. Run Alembic migrations before startup. "
                    f"Missing tables: {', '.join(missing)}"
                )

    # Startup: launch approval SLA expiry background loop
    expiry_task = asyncio.create_task(_approval_expiry_loop())
    retention_task = asyncio.create_task(_retention_loop())
    heartbeat_task = asyncio.create_task(_heartbeat_sweep_loop())

    yield

    # Shutdown: cancel background tasks
    for task in (expiry_task, retention_task, heartbeat_task):
        task.cancel()
        with suppress(asyncio.CancelledError):
            await task

    # Shutdown: close OPA HTTP client pool
    from acr.pillar2_policy.engine import close_opa_client

    await close_opa_client()

    # Shutdown: close Redis and DB pools (hot-path + background)
    await close_redis()
    await engine.dispose()
    await background_engine.dispose()


# ── Application ───────────────────────────────────────────────────────────────

app = FastAPI(
    title="ACR Control Plane",
    description="Agentic Control at Runtime",
    version="1.1.0",
    lifespan=lifespan,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

# Middleware
app.add_middleware(CorrelationMiddleware)


# ── Exception handlers ────────────────────────────────────────────────────────


@app.exception_handler(ACRError)
async def acr_error_handler(request: Request, exc: ACRError) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status_code,
        content={"error_code": exc.error_code, "message": exc.message},
    )


@app.exception_handler(Exception)
async def generic_error_handler(request: Request, exc: Exception) -> JSONResponse:
    # Never expose internal details
    return JSONResponse(
        status_code=500,
        content={"error_code": "INTERNAL_ERROR", "message": "An unexpected error occurred"},
    )


# ── Routers ───────────────────────────────────────────────────────────────────

from acr.gateway.router import router as gateway_router  # noqa: E402
from acr.operator_keys.router import router as operator_keys_router  # noqa: E402
from acr.pillar1_identity.router import router as identity_router  # noqa: E402
from acr.pillar5_containment.router import router as containment_router  # noqa: E402
from acr.pillar6_authority.router import router as authority_router  # noqa: E402
from acr.policy_studio.router import bundle_router  # noqa: E402
from acr.policy_studio.router import router as policy_studio_router  # noqa: E402

app.include_router(gateway_router)
app.include_router(auth_router)
app.include_router(identity_router)
app.include_router(operator_keys_router)
app.include_router(policy_studio_router)
# When require_bundle_auth is False, override the bundle auth dependency with
# a no-op so OPA can poll without credentials (rely on network policy instead).
if not settings.require_bundle_auth:
    from acr.policy_studio.router import _bundle_roles

    app.dependency_overrides[_bundle_roles] = lambda: OperatorPrincipal(
        subject="anonymous-bundle-client", roles=frozenset({"auditor"})
    )

app.include_router(bundle_router)
app.include_router(containment_router)
app.include_router(authority_router)
app.include_router(console_router)
app.mount("/console-assets", console_static_files, name="console-assets")


if settings.acr_env == "development":

    @app.get("/openapi.json", include_in_schema=False)
    async def openapi_schema() -> JSONResponse:
        return JSONResponse(app.openapi())

    @app.get("/docs", include_in_schema=False)
    async def swagger_ui() -> Response:
        return get_swagger_ui_html(openapi_url="/openapi.json", title=f"{app.title} - Swagger UI")

    @app.get("/redoc", include_in_schema=False)
    async def redoc_ui() -> Response:
        return get_redoc_html(openapi_url="/openapi.json", title=f"{app.title} - ReDoc")

else:

    @app.get("/openapi.json", include_in_schema=False)
    async def openapi_schema(
        principal: OperatorPrincipal = Depends(
            require_operator_roles("agent_admin", "security_admin", "auditor")
        ),
    ) -> JSONResponse:
        return JSONResponse(app.openapi())

    @app.get("/docs", include_in_schema=False)
    async def swagger_ui(
        principal: OperatorPrincipal = Depends(
            require_operator_roles("agent_admin", "security_admin", "auditor")
        ),
    ) -> Response:
        return get_swagger_ui_html(openapi_url="/openapi.json", title=f"{app.title} - Swagger UI")

    @app.get("/redoc", include_in_schema=False)
    async def redoc_ui(
        principal: OperatorPrincipal = Depends(
            require_operator_roles("agent_admin", "security_admin", "auditor")
        ),
    ) -> Response:
        return get_redoc_html(openapi_url="/openapi.json", title=f"{app.title} - ReDoc")


# ── Observability endpoints ───────────────────────────────────────────────────

from sqlalchemy import select  # noqa: E402

from acr.db.database import async_session_factory  # noqa: E402
from acr.db.models import TelemetryEventRecord  # noqa: E402


@app.get("/acr/health", tags=["Observability"])
async def health() -> dict:
    return {"status": "healthy", "version": settings.acr_version, "env": settings.acr_env}


@app.get("/acr/live", tags=["Observability"])
async def live() -> dict:
    return {"status": "alive", "version": settings.acr_version}


@app.get("/acr/ready", tags=["Observability"])
async def ready() -> JSONResponse:
    checks: dict[str, str] = {}
    status_code = 200

    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        checks["database"] = "ok"
    except Exception:
        structlog.get_logger(__name__).warning("readiness_check_failed", dependency="database")
        checks["database"] = "error"
        status_code = 503

    try:
        from acr.common.redis_client import get_redis

        await get_redis().ping()
        checks["redis"] = "ok"
    except Exception:
        structlog.get_logger(__name__).warning("readiness_check_failed", dependency="redis")
        checks["redis"] = "error"
        status_code = 503

    try:
        async with httpx.AsyncClient(base_url=settings.opa_url, timeout=3.0) as client:
            from acr.policy_studio.core_bundle import core_identity, operator_identity

            resp = await client.get("/v1/data/acr")
            resp.raise_for_status()
            result = resp.json().get("result") or {}
            if result.get("core_identity") != core_identity() or result.get(
                "operator_identity"
            ) != operator_identity(settings.policy_extension_dir or None):
                raise ValueError("OPA has no compatible managed core bundle")
        checks["opa"] = "ok"
    except Exception:
        structlog.get_logger(__name__).warning("readiness_check_failed", dependency="opa")
        checks["opa"] = "error"
        status_code = 503

    return JSONResponse(
        status_code=status_code,
        content={"status": "ready" if status_code == 200 else "not_ready", "checks": checks},
    )


@app.get("/acr/events", tags=["Observability"])
async def list_events(
    agent_id: str | None = None,
    event_type: str | None = None,
    limit: int = 50,
    db: AsyncSession = Depends(get_db),
    principal: OperatorPrincipal = Depends(
        require_operator_roles("auditor", "agent_admin", "security_admin")
    ),
) -> list[dict]:
    q = select(TelemetryEventRecord).order_by(TelemetryEventRecord.created_at.desc()).limit(limit)
    if agent_id:
        q = q.where(TelemetryEventRecord.agent_id == agent_id)
    if event_type:
        q = q.where(TelemetryEventRecord.event_type == event_type)
    result = await db.execute(q)
    records = result.scalars().all()
    return [r.payload for r in records]


@app.get("/acr/events/{correlation_id}", tags=["Observability"])
async def get_event_chain(
    correlation_id: str,
    db: AsyncSession = Depends(get_db),
    principal: OperatorPrincipal = Depends(
        require_operator_roles("auditor", "agent_admin", "security_admin")
    ),
) -> list[dict]:
    result = await db.execute(
        select(TelemetryEventRecord)
        .where(TelemetryEventRecord.correlation_id == correlation_id)
        .order_by(TelemetryEventRecord.created_at.asc())
    )
    records = result.scalars().all()
    return [r.payload for r in records]


@app.get("/acr/evidence/{correlation_id}", tags=["Observability"])
async def export_evidence_bundle(
    correlation_id: str,
    db: AsyncSession = Depends(get_db),
    principal: OperatorPrincipal = Depends(
        require_operator_roles("auditor", "agent_admin", "security_admin")
    ),
) -> Response:
    result = await db.execute(
        select(TelemetryEventRecord)
        .where(TelemetryEventRecord.correlation_id == correlation_id)
        .order_by(TelemetryEventRecord.created_at.asc())
    )
    records = result.scalars().all()
    artifact = build_evidence_bundle(
        correlation_id=correlation_id,
        events=[record.payload for record in records],
    )
    return Response(
        content=artifact.bytes_data,
        media_type=artifact.content_type,
        headers={
            "Content-Disposition": f'attachment; filename="{artifact.filename}"',
            "X-Evidence-Bundle-Sha256": artifact.sha256,
        },
    )


# ── Drift endpoints ───────────────────────────────────────────────────────────

from acr.pillar1_identity.registry import get_manifest  # noqa: E402
from acr.pillar3_drift.baseline import get_baseline_profile, reset_baseline  # noqa: E402
from acr.pillar3_drift.detector import compute_drift_score  # noqa: E402
from acr.pillar3_drift.governance import (  # noqa: E402
    activate_baseline_version,
    approve_baseline_version,
    list_baseline_versions,
    propose_baseline_version,
    reject_baseline_version,
)
from acr.pillar3_drift.models import (  # noqa: E402
    BaselineProposalRequest,
    BaselineReviewRequest,
    BaselineVersionResponse,
)


@app.get("/acr/drift/{agent_id}", tags=["Drift"])
async def get_drift_score(
    agent_id: str,
    principal: OperatorPrincipal = Depends(
        require_operator_roles("auditor", "agent_admin", "security_admin")
    ),
) -> dict:
    async with async_session_factory() as db:
        drift = await compute_drift_score(db, agent_id)
    return drift.model_dump()


@app.get("/acr/drift/{agent_id}/baseline", tags=["Drift"])
async def get_baseline(
    agent_id: str,
    principal: OperatorPrincipal = Depends(
        require_operator_roles("auditor", "agent_admin", "security_admin")
    ),
) -> dict:
    async with async_session_factory() as db:
        profile = await get_baseline_profile(db, agent_id)
    return profile.model_dump()


@app.post("/acr/drift/{agent_id}/baseline/reset", tags=["Drift"])
async def reset_agent_baseline(
    agent_id: str,
    db: AsyncSession = Depends(get_db),
    principal: OperatorPrincipal = Depends(require_operator_roles("agent_admin", "security_admin")),
) -> dict:
    await reset_baseline(db, agent_id)
    await _emit_baseline_governance_event(
        db=db,
        agent_id=agent_id,
        actor=principal.subject,
        action="baseline_reset",
        reason="Governed baseline reset requested",
        custom={
            "baseline_action": "reset",
            "actor": principal.subject,
        },
    )
    return {"status": "baseline_reset", "agent_id": agent_id}


@app.get(
    "/acr/drift/{agent_id}/baseline/versions",
    response_model=list[BaselineVersionResponse],
    tags=["Drift"],
)
async def get_baseline_versions(
    agent_id: str,
    db: AsyncSession = Depends(get_db),
    principal: OperatorPrincipal = Depends(
        require_operator_roles("auditor", "agent_admin", "security_admin")
    ),
) -> list[BaselineVersionResponse]:
    records = await list_baseline_versions(db, agent_id)
    return [BaselineVersionResponse.model_validate(record) for record in records]


@app.post(
    "/acr/drift/{agent_id}/baseline/propose", response_model=BaselineVersionResponse, tags=["Drift"]
)
async def propose_agent_baseline(
    agent_id: str,
    body: BaselineProposalRequest,
    db: AsyncSession = Depends(get_db),
    principal: OperatorPrincipal = Depends(require_operator_roles("agent_admin", "security_admin")),
) -> BaselineVersionResponse:
    record = await propose_baseline_version(
        db,
        agent_id=agent_id,
        actor=principal.subject,
        window_days=body.window_days,
        notes=body.notes,
    )
    await _emit_baseline_governance_event(
        db=db,
        agent_id=agent_id,
        actor=principal.subject,
        action="baseline_proposed",
        reason="Candidate baseline proposed for review",
        custom={
            "baseline_action": "proposed",
            "baseline_version_id": record.baseline_version_id,
            "window_days": record.window_days,
            "sample_count": record.sample_count,
            "notes": record.notes,
            "actor": principal.subject,
        },
    )
    return BaselineVersionResponse.model_validate(record)


@app.post(
    "/acr/drift/{agent_id}/baseline/{baseline_version_id}/approve",
    response_model=BaselineVersionResponse,
    tags=["Drift"],
)
async def approve_agent_baseline(
    agent_id: str,
    baseline_version_id: str,
    body: BaselineReviewRequest,
    db: AsyncSession = Depends(get_db),
    principal: OperatorPrincipal = Depends(require_operator_roles("security_admin")),
) -> BaselineVersionResponse:
    record = await approve_baseline_version(
        db,
        agent_id=agent_id,
        baseline_version_id=baseline_version_id,
        actor=principal.subject,
        notes=body.notes,
    )
    await _emit_baseline_governance_event(
        db=db,
        agent_id=agent_id,
        actor=principal.subject,
        action="baseline_approved",
        reason="Candidate baseline approved",
        custom={
            "baseline_action": "approved",
            "baseline_version_id": record.baseline_version_id,
            "notes": record.notes,
            "actor": principal.subject,
        },
    )
    return BaselineVersionResponse.model_validate(record)


@app.post(
    "/acr/drift/{agent_id}/baseline/{baseline_version_id}/activate",
    response_model=BaselineVersionResponse,
    tags=["Drift"],
)
async def activate_agent_baseline(
    agent_id: str,
    baseline_version_id: str,
    body: BaselineReviewRequest,
    db: AsyncSession = Depends(get_db),
    principal: OperatorPrincipal = Depends(require_operator_roles("security_admin")),
) -> BaselineVersionResponse:
    record = await activate_baseline_version(
        db,
        agent_id=agent_id,
        baseline_version_id=baseline_version_id,
        actor=principal.subject,
        notes=body.notes,
    )
    await _emit_baseline_governance_event(
        db=db,
        agent_id=agent_id,
        actor=principal.subject,
        action="baseline_activated",
        reason="Approved baseline activated",
        custom={
            "baseline_action": "activated",
            "baseline_version_id": record.baseline_version_id,
            "sample_count": record.sample_count,
            "notes": record.notes,
            "actor": principal.subject,
        },
    )
    return BaselineVersionResponse.model_validate(record)


@app.post(
    "/acr/drift/{agent_id}/baseline/{baseline_version_id}/reject",
    response_model=BaselineVersionResponse,
    tags=["Drift"],
)
async def reject_agent_baseline(
    agent_id: str,
    baseline_version_id: str,
    body: BaselineReviewRequest,
    db: AsyncSession = Depends(get_db),
    principal: OperatorPrincipal = Depends(require_operator_roles("security_admin")),
) -> BaselineVersionResponse:
    record = await reject_baseline_version(
        db,
        agent_id=agent_id,
        baseline_version_id=baseline_version_id,
        actor=principal.subject,
        notes=body.notes,
    )
    await _emit_baseline_governance_event(
        db=db,
        agent_id=agent_id,
        actor=principal.subject,
        action="baseline_rejected",
        reason="Candidate baseline rejected",
        custom={
            "baseline_action": "rejected",
            "baseline_version_id": record.baseline_version_id,
            "notes": record.notes,
            "actor": principal.subject,
        },
    )
    return BaselineVersionResponse.model_validate(record)


async def _emit_baseline_governance_event(
    *,
    db: AsyncSession,
    agent_id: str,
    actor: str,
    action: str,
    reason: str,
    custom: dict,
) -> None:
    correlation_id = get_correlation_id()
    try:
        manifest = await get_manifest(db, agent_id)
        agent_purpose = manifest.purpose
        agent_capabilities = manifest.allowed_tools
    except Exception:
        agent_purpose = "drift baseline governance"
        agent_capabilities = []

    event = build_event(
        event_type="human_intervention",
        agent_id=agent_id,
        agent_purpose=agent_purpose,
        agent_capabilities=agent_capabilities,
        correlation_id=correlation_id,
        session_id=None,
        tool_name="baseline_governance",
        parameters={},
        description=f"Operator action: {action}",
        context={"actor": actor, "baseline_action": action},
        intent={},
        start_time=iso_utcnow(),
        end_time=iso_utcnow(),
        duration_ms=0,
        latency_breakdown=LatencyBreakdown(total_ms=0),
        policies=[],
        output_decision="allow",
        output_reason=reason,
        approval_request_id=None,
        drift_score=None,
        custom=custom,
    )
    await persist_event(db, event)


# ── Metrics endpoint (Prometheus text format) ─────────────────────────────────

from sqlalchemy import func as sa_func  # noqa: E402

from acr.db.models import AgentRecord, ApprovalRequestRecord  # noqa: E402


@app.get("/acr/metrics", tags=["Observability"], response_class=PlainTextResponse)
async def prometheus_metrics(
    principal: OperatorPrincipal = Depends(require_operator_roles("auditor", "security_admin")),
) -> str:
    """
    Expose key ACR metrics in Prometheus text format.
    Includes both OTLP-backed counters and DB-derived gauges.
    Scrape with prometheus/pushgateway or any Prometheus-compatible collector.
    """
    async with async_session_factory() as db:
        # Total events by decision (DB-derived for historical accuracy)
        rows = await db.execute(
            select(
                TelemetryEventRecord.event_type,
                sa_func.count().label("n"),
            ).group_by(TelemetryEventRecord.event_type)
        )
        event_counts = {row.event_type: row.n for row in rows}

        # Approval requests by status
        approval_rows = await db.execute(
            select(
                ApprovalRequestRecord.status,
                sa_func.count().label("n"),
            ).group_by(ApprovalRequestRecord.status)
        )
        approval_counts = {row.status: row.n for row in approval_rows}

        # Active agents
        agent_count_row = await db.execute(
            select(sa_func.count()).where(AgentRecord.is_active == True)  # noqa: E712
        )
        active_agents = agent_count_row.scalar_one()

    lines: list[str] = [
        "# HELP acr_events_total Total telemetry events recorded",
        "# TYPE acr_events_total counter",
    ]
    for event_type, count in event_counts.items():
        lines.append(f'acr_events_total{{event_type="{event_type}"}} {count}')

    lines += [
        "# HELP acr_approval_requests_total Approval requests by status",
        "# TYPE acr_approval_requests_total gauge",
    ]
    for status, count in approval_counts.items():
        lines.append(f'acr_approval_requests_total{{status="{status}"}} {count}')

    lines += [
        "# HELP acr_active_agents Number of active registered agents",
        "# TYPE acr_active_agents gauge",
        f"acr_active_agents {active_agents}",
        "# NOTE: acr.evaluate.total, acr.evaluate.latency, acr.approval.total,",
        "# acr.containment.kills, acr.drift.score are exported via OTLP MeterProvider.",
        "# Configure a Prometheus remote-write or OTLP collector for those metrics.",
        "",  # trailing newline
    ]
    return "\n".join(lines)
