# ACR MCP Gateway

The MCP gateway is an ACR deployable that sits between MCP clients
(agents, IDEs, orchestrators) and an MCP server, and puts every tool
call through the same ACR control plane that guards SDK-wrapped tools:
policy evaluation, the content guardrail, approvals, drift detection,
containment, the kill switch, WS1 observe mode, and durable §18
decision recording with per-agent sequence numbers. It ships as its
own service alongside the gateway, kill switch, and executors.

One gateway instance fronts exactly one upstream MCP server. To guard
several servers, run one gateway per server, each with its own
registered ACR agent identity.

## What is evaluated, and what is not (1.5.0 scope)

| MCP traffic | Handling |
|---|---|
| `tools/list` | Forwarded; the response **pins the tool catalog** (see below). |
| `tools/call` | **Evaluated before forwarding.** The call is forwarded only on an allow decision (or an enforce-mode modify, which forwards the transformed parameters). Deny and escalate are never forwarded. |
| `resources/*`, `prompts/*`, `initialize`, `ping`, notifications | Passed through and logged, **not evaluated**. This is the documented 1.5.0 scope: tools only. |

Because evaluation goes through `POST /acr/evaluate`, proxied calls
inherit the whole stack by construction — there is no parallel policy
path to drift out of sync:

- **Approvals.** An escalate decision returns an error result to the
  MCP client naming the `approval_request_id`. The client retries the
  identical call after an operator approves; the retry is a fresh
  evaluation and proceeds if policy now allows it.
- **Observe mode (WS1).** If the gateway's agent is in observe mode,
  the evaluate response carries the would-be decision and the proxy
  forwards the client's *original* arguments, exactly as the direct
  path behaves. Observe is a property of the gateway's agent record;
  the proxy cannot set it and clients cannot request it.
- **Modify.** Transformed parameters from the decision replace the
  client's arguments before forwarding (enforce mode).
- **Execution short-circuit.** If the control plane returns an
  `execution_result` with the decision (executor-backed actions), the
  proxy returns it without contacting the upstream — no double
  execution.
- **Fail closed.** If evaluation fails, times out, or the session
  cannot be established, the call is not forwarded. The client gets an
  error result; nothing reaches the server.

## Tool catalog pinning (tool-list poisoning defense)

The first `tools/list` response pins each tool's definition: a SHA-256
over the canonical `{name, description, inputSchema}`. On every later
list, definitions are re-hashed:

- A tool whose definition **changed** is marked changed. In the
  default `enforce` pinning mode, its calls are blocked with an error
  naming the change; other tools are unaffected. In `log` mode, calls
  proceed to evaluation with `tool_definition_changed: true` stamped
  into the evaluation context, so policy can decide.
- A tool that was **never listed** is never forwarded, in either mode.
  A name that exists on some other server means nothing here — this is
  the cross-server confusion gate.
- Restoring the original definition does **not** un-pin a changed
  tool. Re-pinning is an operator action: review the new definition,
  then restart the gateway. A silent re-pin would make the poisoning
  window undetectable.

The catalog is per gateway process and per upstream; it is not shared
between replicas (see Deployment notes).

## Response path

Upstream results pass back through the pillar-2 output filter before
reaching the client: `structuredContent` is filtered with the same
parameter rules used for tool inputs, and text content is pattern-
redacted (JSON-encoded text is filtered as an object first). A result
larger than `MCP_GATEWAY_MAX_RESPONSE_BYTES` (default 1 MiB) is
replaced with an error result — oversized payloads are never delivered
and never truncated into the client.

## The bypass requirement (read this before deploying)

**The proxy cannot prevent a client from connecting to the MCP server
directly.** Nothing in this service stops a process that can reach the
server's address from skipping the gateway entirely. Preventing direct-
to-server bypass is a **deployment and network-placement requirement**
that the operator owns:

- The upstream MCP server must accept connections **only** from the
  gateway — network policy, security groups, firewall rules, or a
  private subnet/namespace with the gateway as the sole ingress.
- Clients must be configured with the gateway's endpoint, and the
  server's address must not be published to client environments.
- In the shipped Kubernetes base, place the MCP server in the same
  namespace behind a NetworkPolicy that admits traffic only from the
  `acr-mcp-gateway` pods. In Compose, put the server on a network the
  clients are not attached to (the validation overlay wires it this
  way: clients reach the proxy on 8080; the fixture server has no
  published port).

If a deployment cannot meet this placement requirement, the gateway
still governs all traffic that flows through it — but it must not be
described, to auditors or to yourself, as governing the server.

## Configuration

Environment variables (see `src/acr/mcp_gateway/service.py`):

| Variable | Required | Default | Meaning |
|---|---|---|---|
| `MCP_GATEWAY_UPSTREAM_URL` | yes | — | Streamable-HTTP endpoint of the one upstream MCP server. |
| `MCP_GATEWAY_UPSTREAM_ID` | no | host of upstream URL | Server identity stamped into evaluation context (`mcp.server_id`). |
| `MCP_GATEWAY_AGENT_ID` | no | `acr-mcp-gateway` | The gateway's own registered ACR agent id. Register it like any agent; its allowed-tools and policy bundle decide what may be forwarded. |
| `MCP_GATEWAY_OPERATOR_API_KEY` | one of the two credentials | — | Operator API key used to issue the gateway's agent session. |
| `MCP_GATEWAY_AGENT_TOKEN` | one of the two credentials | — | Pre-issued agent JWT (skips session issuance). |
| `ACR_GATEWAY_URL` | no | `http://localhost:8000` | ACR control-plane base URL. |
| `MCP_GATEWAY_MAX_RESPONSE_BYTES` | no | `1048576` | Response size cap. |
| `MCP_GATEWAY_TOOL_PINNING` | no | `enforce` | `enforce` blocks changed tools; `log` stamps context and lets policy decide. |
| `MCP_GATEWAY_TIMEOUT_SECONDS` | no | `30` | HTTP timeout for evaluation and upstream calls. |

Endpoints: `POST /mcp` (also `/`) accepts one JSON-RPC message
(batches are rejected); notifications return 202. `GET /health`
reports liveness and whether the catalog is pinned.

## Deployment

- **Compose:** the `acr-mcp-gateway` service in `docker-compose.yml`
  is profile-gated (`--profile mcp-gateway`) because the upstream is
  deployment-specific. `docker-compose.mcp-gateway-test.yml` adds a
  fixture MCP server for validation stacks and red-team category 11.
- **Kubernetes:** `deploy/k8s/base/mcp-gateway-deployment.yaml` and
  `mcp-gateway-service.yaml` (in the base kustomization). The operator
  key comes from the existing `acr-gateway-secret`.
- **Dockerfile:** `Dockerfile.mcp-gateway`, port 8080.

Deployment notes:

- The service is stateless except for the in-process tool catalog,
  and that catalog is **per process**: it lives in the memory of the
  single gateway process that served the lists. Run the gateway as
  exactly one process (the shipped image sets `WEB_CONCURRENCY=1`,
  the reference compose stack defaults `MCP_GATEWAY_WORKERS` to 1,
  and the service refuses to start with more than one worker)
  and one instance per upstream server. Multiple workers or replicas
  each hold their own catalog: a definition change is only detected
  by a process that serves a list after the change, while a call can
  land on another process whose catalog still shows the tool
  unchanged — so pinning enforcement is NOT identical across
  processes, and multi-process deployment silently weakens it
  (red-team finding F-4, 2026-11-23). Shared catalog state for
  scale-out is future work, not a v1.5.0 claim.
- Transports: streamable HTTP (JSON and SSE responses) in 1.5.0. The
  deprecated HTTP+SSE two-endpoint transport and stdio are not
  supported by the gateway service; run stdio servers behind a
  streamable-HTTP bridge if they must be proxied.
- Red-team coverage: category 1 probes replayed through the proxy
  deny identically to the direct path (pytest parity suite), and
  harness category 11 covers poisoning, cross-server confusion, and
  oversized responses against a live stack.
