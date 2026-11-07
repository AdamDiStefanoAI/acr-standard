"""Isolated real-span probe; never exports traces or changes database contents.

Run in a subprocess because OpenTelemetry providers and instrumentors are global.
Only in-memory SQLite and an explicitly selected loopback test Postgres are used.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys

from fastapi import FastAPI
from opentelemetry import trace
from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.sdk.trace.sampling import ALWAYS_ON
from opentelemetry.trace import SpanKind, StatusCode
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import create_async_engine

from acr.pillar4_observability.otel import acr_span, setup_telemetry


def main() -> None:
    mode = sys.argv[1]
    assert mode in {"sync", "async"}
    url = os.environ.get("ACR_TRACING_TEST_DATABASE_URL")
    if url is None:
        url = "sqlite:///:memory:" if mode == "sync" else "sqlite+aiosqlite:///:memory:"
    parsed = make_url(url)
    if parsed.get_backend_name() == "sqlite":
        assert parsed.database == ":memory:", "Only in-memory SQLite is allowed"
    else:
        assert mode == "async" and parsed.drivername == "postgresql+asyncpg"
        assert parsed.host in {"localhost", "127.0.0.1", "::1"}, "Test Postgres must be local"

    exporter = InMemorySpanExporter()
    provider = TracerProvider(sampler=ALWAYS_ON)
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    trace.set_tracer_provider(provider)

    # Match application startup: the engine already exists when setup runs.
    engine = create_engine(url) if mode == "sync" else create_async_engine(url)
    setup_telemetry(FastAPI(), engine)
    assert SQLAlchemyInstrumentor().is_instrumented_by_opentelemetry, (
        "SQLAlchemy tracing did not attach; check the resolved dependency versions"
    )

    async def query_async() -> None:
        try:
            async with engine.connect() as connection:
                result = await connection.execute(text("SELECT 1"))
                assert result.scalar_one() == 1
        finally:
            await engine.dispose()

    with acr_span("acr.database-tracing-test") as parent:
        if mode == "async":
            asyncio.run(query_async())
        else:
            try:
                with engine.connect() as connection:
                    assert connection.execute(text("SELECT 1")).scalar_one() == 1
            finally:
                engine.dispose()

    provider.force_flush()
    spans = exporter.get_finished_spans()
    queries = [
        span
        for span in spans
        if span.attributes.get("db.statement", span.attributes.get("db.query.text")) == "SELECT 1"
    ]
    assert len(queries) == 1, f"Expected one real database query span, got {len(queries)}"
    query = queries[0]
    assert query.kind == SpanKind.CLIENT
    assert query.instrumentation_scope.name == "opentelemetry.instrumentation.sqlalchemy"
    assert query.attributes.get("db.system", query.attributes.get("db.system.name")) == (
        parsed.get_backend_name()
    )
    assert query.context.trace_id == parent.get_span_context().trace_id
    assert query.parent.span_id == parent.get_span_context().span_id
    assert query.status.status_code != StatusCode.ERROR
    provider.shutdown()
    print(json.dumps({"database": parsed.get_backend_name(), "mode": mode, "query_spans": 1}))


if __name__ == "__main__":
    main()
