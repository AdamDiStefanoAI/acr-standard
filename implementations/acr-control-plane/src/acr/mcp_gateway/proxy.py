"""MCP gateway proxy core (v1.5.0 WS5).

The proxy sits between MCP clients and one upstream MCP server. It is a
JSON-RPC message handler, deliberately transport-thin: the deployable
service (acr.mcp_gateway.service) terminates streamable HTTP from
clients and speaks streamable HTTP to the upstream, while tests drive
this class directly with an in-process upstream.

Enforcement model — the same one the SDK guards use. The proxy holds an
ACR agent session for the identity it represents, and every
``tools/call`` is evaluated through ``POST /acr/evaluate`` BEFORE
anything is forwarded. That single fact is what puts proxied calls
under the full control-plane stack with no parallel implementation:

- decisions are recorded durably with a per-agent sequence (§18) by the
  gateway's recording path, exactly as for a guarded framework call;
- policy, approval (pillar 6), drift, graduated containment, and the
  kill switch all apply because they live behind the evaluate endpoint;
- observe mode (WS1) is respected the same way the gateway respects it:
  an observe-mode evaluation returns decision ``allow`` with
  ``would_be_decision`` set and no modified action, so the proxy
  forwards the client's original arguments and changes nothing.

Fail-closed throughout: if evaluation fails, errors, or is unavailable,
the call is NOT forwarded. A tool the upstream never listed is not
forwarded. A tool whose definition changed after the catalog was
pinned is not forwarded (default; see ``tool_pinning``).

Protocol scope for 1.5.0: tools only. ``tools/list`` is forwarded and
the returned catalog is pinned for change detection. ``resources/*``
and ``prompts/*`` (and any other method) are passed through and logged,
never evaluated; evaluating them is a 1.6 conversation.

What the proxy cannot do, by construction: stop a client that can reach
the MCP server directly. Bypass prevention is a deployment requirement
(network placement: the server must only be reachable through the
proxy), documented in docs/mcp-gateway.md. The proxy does not silently
imply otherwise.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Protocol

import structlog

from acr.gateway.models import EvaluateResponse
from acr.pillar2_policy.output_filter import filter_parameters, redact_parameters
from acr.sdk.errors import ACRHTTPError

logger = structlog.get_logger(__name__)

# JSON-RPC error codes (protocol range) plus one server-defined code.
ERR_INVALID_REQUEST = -32600
ERR_METHOD_NOT_FOUND = -32601
ERR_UPSTREAM = -32000
ERR_OVERSIZED = -32001

_PASS_THROUGH_PREFIXES = ("resources/", "prompts/")
_EVALUATED_METHOD = "tools/call"
_LIST_METHOD = "tools/list"


class UpstreamTransport(Protocol):
    """One upstream MCP server, spoken to in JSON-RPC messages.

    ``send`` returns (response_message, upstream_session_id); the
    response is None for notifications. Implementations raise on
    transport failure, which the proxy turns into a JSON-RPC error —
    never into a silently forwarded or retried call.
    """

    async def send(
        self, message: dict[str, Any], *, session_id: str | None
    ) -> tuple[dict[str, Any] | None, str | None]: ...


@dataclass(frozen=True)
class ProxyConfig:
    """Static proxy configuration (env-bound in the service module)."""

    server_id: str
    # Maximum serialized size of an upstream response's result before the
    # proxy replaces it with an error. Oversized responses are a
    # category-3 red-team surface (context flooding / smuggled payloads).
    max_response_bytes: int = 1_048_576
    # "enforce": a tool whose definition changed after pinning is blocked
    # at the proxy. "log": the change is logged and stamped into the
    # evaluation context, and policy decides.
    tool_pinning: str = "enforce"


@dataclass
class _CatalogEntry:
    pinned_hash: str
    definition: dict[str, Any]
    changed: bool = False
    observed_hash: str | None = None


@dataclass
class ToolCatalog:
    """The pinned tool catalog for the upstream server.

    The first observed ``tools/list`` pins every definition. A later
    list that changes a tool's name/description/inputSchema marks the
    tool changed: the swap is exactly the tool-list poisoning move
    (approve under definition A, call under definition B), so the change
    is surfaced loudly instead of being absorbed silently.
    """

    entries: dict[str, _CatalogEntry] = field(default_factory=dict)
    version: int = 0

    @staticmethod
    def definition_hash(tool: dict[str, Any]) -> str:
        canonical = {
            "name": tool.get("name"),
            "description": tool.get("description"),
            "inputSchema": tool.get("inputSchema"),
        }
        blob = json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(blob).hexdigest()

    def observe(self, tools: list[dict[str, Any]], *, server_id: str) -> None:
        for tool in tools:
            if not isinstance(tool, dict) or not tool.get("name"):
                continue
            name = str(tool["name"])
            digest = self.definition_hash(tool)
            entry = self.entries.get(name)
            if entry is None:
                self.entries[name] = _CatalogEntry(pinned_hash=digest, definition=tool)
                self.version += 1
                logger.info("mcp_tool_pinned", server_id=server_id, tool=name, sha256=digest)
            elif digest != entry.pinned_hash and digest != entry.observed_hash:
                entry.changed = True
                entry.observed_hash = digest
                self.version += 1
                logger.warning(
                    "mcp_tool_definition_changed",
                    server_id=server_id,
                    tool=name,
                    pinned_sha256=entry.pinned_hash,
                    observed_sha256=digest,
                )

    def get(self, name: str) -> _CatalogEntry | None:
        return self.entries.get(name)


def _tool_error_result(text: str) -> dict[str, Any]:
    """An MCP tool result carrying an error (the protocol's tool-error shape)."""
    return {"content": [{"type": "text", "text": text}], "isError": True}


def _rpc_result(request_id: Any, result: Any) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _rpc_error(request_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


class McpProxy:
    """Evaluates tools/call through ACR, forwards what is authorized.

    ``session`` is duck-typed like the SDK guard sessions: an object
    with ``evaluate_action(tool_name=..., parameters=...,
    description=..., context=..., intent=...)`` returning an
    EvaluateResponse (awaited when it returns an awaitable). In
    production this is an AsyncACRAgentSession bound to the proxy's own
    registered agent identity.
    """

    def __init__(
        self,
        *,
        config: ProxyConfig,
        session: Any,
        upstream: UpstreamTransport,
        session_refresher: Any | None = None,
    ) -> None:
        self._config = config
        self._session = session
        self._upstream = upstream
        self._session_refresher = session_refresher
        self.catalog = ToolCatalog()
        self._catalog_loaded = False
        self._upstream_session_id: str | None = None

    # ── entry point ──────────────────────────────────────────────────────

    async def handle(self, message: dict[str, Any]) -> dict[str, Any] | None:
        """Handle one JSON-RPC message. Returns the response, or None
        for notifications (which have no response by definition)."""
        if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
            return _rpc_error(
                message.get("id") if isinstance(message, dict) else None,
                ERR_INVALID_REQUEST,
                "Expected a single JSON-RPC 2.0 message object",
            )
        method = message.get("method")
        is_notification = "id" not in message

        if method == _EVALUATED_METHOD and not is_notification:
            return await self._handle_tools_call(message)
        if method == _LIST_METHOD and not is_notification:
            return await self._handle_tools_list(message)
        return await self._forward(message, is_notification=is_notification)

    # ── tools/list ───────────────────────────────────────────────────────

    async def _handle_tools_list(self, message: dict[str, Any]) -> dict[str, Any] | None:
        response = await self._forward_raw(message)
        if response is not None:
            result = response.get("result")
            if isinstance(result, dict) and isinstance(result.get("tools"), list):
                self.catalog.observe(result["tools"], server_id=self._config.server_id)
                self._catalog_loaded = True
            response = self._cap_response(message, response)
        return response

    async def _ensure_catalog(self) -> None:
        """Load the catalog proxy-side if the client never listed.

        A client that calls without listing first must not find an empty
        catalog treated as 'everything unknown, deny all' nor as 'no
        catalog, forward anything'. The proxy lists on the server's
        behalf once, pins what it sees, and applies the same gates.
        """
        if self._catalog_loaded:
            return
        probe = {"jsonrpc": "2.0", "id": "acr-proxy-catalog", "method": _LIST_METHOD}
        response, session_id = await self._upstream.send(
            probe, session_id=self._upstream_session_id
        )
        if session_id:
            self._upstream_session_id = session_id
        if response is not None:
            result = response.get("result")
            if isinstance(result, dict) and isinstance(result.get("tools"), list):
                self.catalog.observe(result["tools"], server_id=self._config.server_id)
        self._catalog_loaded = True

    # ── tools/call ───────────────────────────────────────────────────────

    async def _handle_tools_call(self, message: dict[str, Any]) -> dict[str, Any]:
        request_id = message.get("id")
        params = message.get("params") or {}
        tool_name = params.get("name")
        arguments = params.get("arguments") or {}
        if not isinstance(tool_name, str) or not tool_name:
            return _rpc_error(request_id, ERR_INVALID_REQUEST, "tools/call requires params.name")
        if not isinstance(arguments, dict):
            return _rpc_error(
                request_id, ERR_INVALID_REQUEST, "tools/call params.arguments must be an object"
            )

        await self._ensure_catalog()
        entry = self.catalog.get(tool_name)
        if entry is None:
            # Fail closed: the upstream never listed this tool. Forwarding
            # it would let a client invoke server surface the proxy has
            # never seen — the cross-server confusion shape, where a name
            # meaningful on one server is aimed at another.
            logger.warning(
                "mcp_call_unknown_tool", server_id=self._config.server_id, tool=tool_name
            )
            return _rpc_result(
                request_id,
                _tool_error_result(
                    f"ACR MCP gateway: tool '{tool_name}' is not in the pinned "
                    f"catalog for server '{self._config.server_id}'; the call "
                    "was not forwarded."
                ),
            )
        if entry.changed and self._config.tool_pinning == "enforce":
            logger.warning(
                "mcp_call_blocked_definition_changed",
                server_id=self._config.server_id,
                tool=tool_name,
            )
            return _rpc_result(
                request_id,
                _tool_error_result(
                    f"ACR MCP gateway: the definition of tool '{tool_name}' "
                    "changed after the catalog was pinned (possible tool-list "
                    "poisoning); the call was not forwarded. An operator must "
                    "review the new definition and restart the gateway to "
                    "re-pin the catalog."
                ),
            )

        context = {
            "mcp": {
                "server_id": self._config.server_id,
                "tool_definition_sha256": entry.pinned_hash,
                "tool_definition_changed": entry.changed,
                "catalog_version": self.catalog.version,
                "transport": "acr-mcp-gateway",
            }
        }
        description = entry.definition.get("description")
        try:
            response = await self._evaluate(
                tool_name=tool_name,
                parameters=arguments,
                description=description if isinstance(description, str) else None,
                context=context,
            )
        except Exception as exc:  # evaluation unavailable → fail closed
            logger.error(
                "mcp_evaluate_failed",
                server_id=self._config.server_id,
                tool=tool_name,
                error=str(exc),
            )
            return _rpc_result(
                request_id,
                _tool_error_result(
                    "ACR MCP gateway: policy evaluation was unavailable; "
                    "failing closed. The call was not forwarded."
                ),
            )

        correlation = response.correlation_id or "unknown"
        if response.decision == "deny":
            logger.info(
                "mcp_call_denied",
                server_id=self._config.server_id,
                tool=tool_name,
                correlation_id=correlation,
                reason=response.reason,
            )
            return _rpc_result(
                request_id,
                _tool_error_result(
                    f"ACR denied this tool call: {response.reason or 'policy denied'} "
                    f"(correlation_id={correlation}). The call was not forwarded."
                ),
            )
        if response.decision == "escalate":
            logger.info(
                "mcp_call_escalated",
                server_id=self._config.server_id,
                tool=tool_name,
                correlation_id=correlation,
                approval_request_id=response.approval_request_id,
            )
            return _rpc_result(
                request_id,
                _tool_error_result(
                    "ACR requires human approval before this tool call can "
                    f"proceed (approval_request_id={response.approval_request_id}, "
                    f"correlation_id={correlation}). The call was not forwarded; "
                    "retry the call after the request is approved."
                ),
            )
        if response.execution_result is not None:
            # The control plane executed the action itself (gateway-side
            # execution deployments). Forwarding as well would execute twice.
            return _rpc_result(
                request_id,
                self._execution_result_payload(response.execution_result),
            )

        forward = dict(message)
        if response.decision == "modify" and response.modified_action is not None:
            # Enforce-mode modify: the gateway's transformed parameters
            # replace the client's before forwarding. (Observe mode never
            # reaches here with a modified action: its responses carry the
            # original action and decision "allow".)
            forward["params"] = {
                **params,
                "arguments": dict(response.modified_action.parameters),
            }
            logger.info(
                "mcp_call_modified",
                server_id=self._config.server_id,
                tool=tool_name,
                correlation_id=correlation,
            )
        upstream_response = await self._forward_raw(forward)
        if upstream_response is None:
            return _rpc_error(request_id, ERR_UPSTREAM, "Upstream returned no response")
        upstream_response = self._cap_response(message, upstream_response)
        if "result" in upstream_response:
            filtered, was_filtered = self._filter_tool_result(
                tool_name, upstream_response["result"], correlation
            )
            if was_filtered:
                logger.info(
                    "mcp_result_output_filtered",
                    server_id=self._config.server_id,
                    tool=tool_name,
                    correlation_id=correlation,
                )
            upstream_response = {**upstream_response, "result": filtered}
        return upstream_response

    async def _evaluate(self, **kwargs: Any) -> EvaluateResponse:
        pending = self._session.evaluate_action(**kwargs)
        if hasattr(pending, "__await__"):
            try:
                return await pending
            except ACRHTTPError as exc:
                if exc.status_code != 401 or self._session_refresher is None:
                    raise
                # Agent token expired mid-flight: refresh once and retry,
                # mirroring the session's own refresh_token contract.
                refreshed = self._session_refresher()
                if hasattr(refreshed, "__await__"):
                    await refreshed
                retry = self._session.evaluate_action(**kwargs)
                return await retry if hasattr(retry, "__await__") else retry
        return pending

    @staticmethod
    def _execution_result_payload(execution_result: Any) -> dict[str, Any]:
        if isinstance(execution_result, dict) and "content" in execution_result:
            return execution_result
        payload: dict[str, Any] = {
            "content": [{"type": "text", "text": json.dumps(execution_result, default=str)}]
        }
        if isinstance(execution_result, dict):
            payload["structuredContent"] = execution_result
        return payload

    # ── output filter (responses on the way back) ────────────────────────

    @staticmethod
    def _filter_tool_result(tool_name: str, result: Any, correlation_id: str) -> tuple[Any, bool]:
        """Run the pillar-2 output filter over a tool result.

        The same redaction the gateway applies to action parameters is
        applied to what the server returns: structuredContent directly,
        and text content items (JSON-encoded objects are filtered as
        objects; plain text is pattern-redacted).
        """
        if not isinstance(result, dict):
            return result, False
        modified = False
        out = dict(result)
        structured = out.get("structuredContent")
        if isinstance(structured, dict):
            filtered = filter_parameters(tool_name, structured, correlation_id)
            out["structuredContent"] = filtered.parameters
            modified = modified or filtered.was_modified
        content = out.get("content")
        if isinstance(content, list):
            new_content: list[Any] = []
            for item in content:
                if (
                    isinstance(item, dict)
                    and item.get("type") == "text"
                    and isinstance(item.get("text"), str)
                ):
                    text = item["text"]
                    try:
                        parsed = json.loads(text)
                    except (ValueError, TypeError):
                        parsed = None
                    if isinstance(parsed, dict):
                        filtered = filter_parameters(tool_name, parsed, correlation_id)
                        if filtered.was_modified:
                            item = {**item, "text": json.dumps(filtered.parameters)}
                            modified = True
                    else:
                        cleaned, found = redact_parameters({"value": text})
                        if found:
                            item = {**item, "text": cleaned["value"]}
                            modified = True
                new_content.append(item)
            out["content"] = new_content
        return out, modified

    # ── forwarding ───────────────────────────────────────────────────────

    async def _forward(
        self, message: dict[str, Any], *, is_notification: bool
    ) -> dict[str, Any] | None:
        method = str(message.get("method") or "")
        if method.startswith(_PASS_THROUGH_PREFIXES):
            logger.info(
                "mcp_pass_through",
                server_id=self._config.server_id,
                method=method,
                note="passed through and logged, not evaluated (1.5.0 scope)",
            )
        response = await self._forward_raw(message)
        if response is not None and not is_notification:
            response = self._cap_response(message, response)
        return response

    async def _forward_raw(self, message: dict[str, Any]) -> dict[str, Any] | None:
        try:
            response, session_id = await self._upstream.send(
                message, session_id=self._upstream_session_id
            )
        except Exception as exc:
            logger.error(
                "mcp_upstream_failed",
                server_id=self._config.server_id,
                method=message.get("method"),
                error=str(exc),
            )
            return _rpc_error(message.get("id"), ERR_UPSTREAM, f"Upstream MCP server error: {exc}")
        if session_id:
            self._upstream_session_id = session_id
        return response

    def _cap_response(
        self, request_message: dict[str, Any], response: dict[str, Any]
    ) -> dict[str, Any]:
        result = response.get("result")
        if result is None:
            return response
        size = len(json.dumps(result, default=str).encode())
        if size <= self._config.max_response_bytes:
            return response
        logger.warning(
            "mcp_response_oversized",
            server_id=self._config.server_id,
            method=request_message.get("method"),
            size_bytes=size,
            max_bytes=self._config.max_response_bytes,
        )
        if request_message.get("method") == _EVALUATED_METHOD:
            return _rpc_result(
                request_message.get("id"),
                _tool_error_result(
                    "ACR MCP gateway: the upstream response exceeded the "
                    f"configured maximum size ({size} bytes > "
                    f"{self._config.max_response_bytes}); it was not delivered."
                ),
            )
        return _rpc_error(
            request_message.get("id"),
            ERR_OVERSIZED,
            "Upstream response exceeded the ACR MCP gateway's configured "
            "maximum size and was not delivered.",
        )
