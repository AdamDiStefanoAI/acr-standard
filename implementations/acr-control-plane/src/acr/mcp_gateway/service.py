"""ACR MCP Gateway Service (v1.5.0 WS5).

This runs as a SEPARATE FastAPI service in its own container
(port 8080), alongside the gateway / killswitch / executor. It must NOT
run inside the gateway process: it holds its own registered ACR agent
identity and evaluates every proxied tools/call through the gateway's
``POST /acr/evaluate`` like any other guarded client.

Deployment contract (see docs/mcp-gateway.md): one gateway instance
fronts exactly one upstream MCP server, and the upstream must be
network-reachable ONLY through this service. A client that can reach
the server directly bypasses the proxy entirely; preventing that is a
network-placement requirement of the deployment, not something this
service can enforce or detect.

Configuration (environment):
  MCP_GATEWAY_UPSTREAM_URL      upstream MCP server endpoint (required)
  MCP_GATEWAY_UPSTREAM_ID       server identity stamped into evaluation
                                context (default: upstream host)
  MCP_GATEWAY_AGENT_ID          the proxy's registered ACR agent id
                                (default: acr-mcp-gateway)
  MCP_GATEWAY_OPERATOR_API_KEY  operator key used to issue/refresh the
                                agent token (one of this or the token)
  MCP_GATEWAY_AGENT_TOKEN       a pre-issued agent token (alternative)
  ACR_GATEWAY_URL               control plane base URL
                                (default: http://localhost:8000)
  MCP_GATEWAY_MAX_RESPONSE_BYTES  upstream result size cap (default 1MiB)
  MCP_GATEWAY_TOOL_PINNING      "enforce" (default) or "log"
  MCP_GATEWAY_TIMEOUT_SECONDS   upstream HTTP timeout (default 30)
  WEB_CONCURRENCY               must be 1 (the default): the pinned tool
                                catalog is per-process state, and the
                                service refuses to start with more than
                                one worker (red-team finding F-4)
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from typing import Any
from urllib.parse import urlsplit

import structlog
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

from acr.mcp_gateway.proxy import McpProxy, ProxyConfig
from acr.mcp_gateway.upstream import HttpUpstream
from acr.sdk.client import AsyncACRClient

logger = structlog.get_logger(__name__)


def _config_from_env() -> ProxyConfig:
    upstream_url = os.environ.get("MCP_GATEWAY_UPSTREAM_URL", "")
    server_id = os.environ.get("MCP_GATEWAY_UPSTREAM_ID") or (
        urlsplit(upstream_url).netloc or "upstream"
    )
    return ProxyConfig(
        server_id=server_id,
        max_response_bytes=int(os.environ.get("MCP_GATEWAY_MAX_RESPONSE_BYTES", "1048576")),
        tool_pinning=os.environ.get("MCP_GATEWAY_TOOL_PINNING", "enforce"),
    )


async def _build_proxy() -> McpProxy:
    upstream_url = os.environ.get("MCP_GATEWAY_UPSTREAM_URL", "")
    if not upstream_url:
        raise RuntimeError("MCP_GATEWAY_UPSTREAM_URL is required")
    agent_id = os.environ.get("MCP_GATEWAY_AGENT_ID", "acr-mcp-gateway")
    operator_key = os.environ.get("MCP_GATEWAY_OPERATOR_API_KEY") or None
    client = AsyncACRClient(
        base_url=os.environ.get("ACR_GATEWAY_URL", "http://localhost:8000"),
        operator_api_key=operator_key,
    )
    static_token = os.environ.get("MCP_GATEWAY_AGENT_TOKEN")
    if static_token:
        session = client.create_agent_session(agent_id, static_token)
        refresher = None
    else:
        # Issues a fresh agent token via the operator key; the session's
        # own refresh path re-issues on expiry.
        session = await client.issue_agent_session(agent_id)
        refresher = session.refresh_token
    upstream = HttpUpstream(
        upstream_url,
        timeout_seconds=float(os.environ.get("MCP_GATEWAY_TIMEOUT_SECONDS", "30")),
    )
    logger.info(
        "mcp_gateway_configured",
        upstream_id=_config_from_env().server_id,
        agent_id=agent_id,
    )
    return McpProxy(
        config=_config_from_env(),
        session=session,
        upstream=upstream,
        session_refresher=refresher,
    )


def _enforce_single_process() -> None:
    """Refuse a multi-worker deployment (red-team finding F-4).

    Uvicorn honors WEB_CONCURRENCY, and the pinned tool catalog lives in
    each process's own memory: with more than one worker, a tool-list
    poisoning observed by one worker does not block calls landing on
    another whose catalog still shows the tool unchanged. That failure
    is silent, so the service fails closed at startup instead of
    running with split enforcement.
    """
    raw = os.environ.get("WEB_CONCURRENCY", "1")
    try:
        workers = int(raw)
    except ValueError:
        raise RuntimeError(f"WEB_CONCURRENCY must be an integer, got {raw!r}") from None
    if workers != 1:
        raise RuntimeError(
            "acr-mcp-gateway must run as exactly one process "
            f"(WEB_CONCURRENCY=1); got WEB_CONCURRENCY={raw}. The pinned "
            "tool catalog is per-process state: multiple workers silently "
            "split tool-pinning enforcement (red-team finding F-4). Run "
            "one gateway instance per upstream MCP server instead."
        )


def create_app(proxy: McpProxy | None = None) -> FastAPI:
    """Build the service app. Tests inject a pre-built proxy."""

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        if proxy is not None:
            app.state.proxy = proxy
        else:
            _enforce_single_process()
            app.state.proxy = await _build_proxy()
        yield

    app = FastAPI(title="ACR MCP Gateway", version="1.5.0", lifespan=lifespan)
    if proxy is not None:
        app.state.proxy = proxy

    @app.get("/health")
    async def health() -> dict[str, Any]:
        return {"status": "ok", "service": "acr-mcp-gateway"}

    @app.post("/mcp")
    @app.post("/")
    async def mcp_endpoint(request: Request) -> Response:
        try:
            message = await request.json()
        except Exception:
            return JSONResponse(
                status_code=400,
                content={
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32700, "message": "Parse error"},
                },
            )
        if isinstance(message, list):
            return JSONResponse(
                status_code=400,
                content={
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {
                        "code": -32600,
                        "message": "JSON-RPC batches are not supported; "
                        "send one message per request",
                    },
                },
            )
        active: McpProxy = request.app.state.proxy
        response = await active.handle(message)
        if response is None:
            return Response(status_code=202)
        return JSONResponse(content=response)

    return app


app = create_app()
