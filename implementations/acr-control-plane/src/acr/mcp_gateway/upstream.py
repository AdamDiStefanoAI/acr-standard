"""Streamable-HTTP transport to the upstream MCP server.

One POST per JSON-RPC message. The upstream may answer with a plain
JSON body or with a ``text/event-stream`` body (both are legal
streamable-HTTP responses); SSE bodies are scanned for the JSON-RPC
response matching the request id. The upstream's ``Mcp-Session-Id``
header is captured and replayed, per the transport contract.
"""

from __future__ import annotations

import json
from typing import Any

import httpx


class HttpUpstream:
    def __init__(
        self,
        url: str,
        *,
        timeout_seconds: float = 30.0,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self._url = url
        self._owns_client = client is None
        # trust_env=False: service-to-service traffic must not be routed
        # through ambient HTTP(S)_PROXY settings, and a malformed proxy
        # env must never take the gateway down at startup.
        self._client = client or httpx.AsyncClient(timeout=timeout_seconds, trust_env=False)

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    async def send(
        self, message: dict[str, Any], *, session_id: str | None
    ) -> tuple[dict[str, Any] | None, str | None]:
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        if session_id:
            headers["Mcp-Session-Id"] = session_id
        response = await self._client.post(self._url, json=message, headers=headers)
        new_session = response.headers.get("mcp-session-id") or session_id
        if "id" not in message:
            # Notification: the transport acknowledges with 202 and no body.
            return None, new_session
        if response.status_code == 202 or not response.content:
            return None, new_session
        response.raise_for_status()
        content_type = response.headers.get("content-type", "")
        if "text/event-stream" in content_type:
            return self._parse_sse(response.text, message.get("id")), new_session
        parsed = response.json()
        return (parsed if isinstance(parsed, dict) else None), new_session

    @staticmethod
    def _parse_sse(body: str, request_id: Any) -> dict[str, Any] | None:
        """Extract the JSON-RPC response for request_id from an SSE body."""
        fallback: dict[str, Any] | None = None
        for line in body.splitlines():
            if not line.startswith("data:"):
                continue
            payload = line[len("data:") :].strip()
            if not payload:
                continue
            try:
                parsed = json.loads(payload)
            except ValueError:
                continue
            if not isinstance(parsed, dict):
                continue
            if parsed.get("id") == request_id:
                return parsed
            if "result" in parsed or "error" in parsed:
                fallback = parsed
        return fallback
