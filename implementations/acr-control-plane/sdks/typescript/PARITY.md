# Python / TypeScript SDK parity

Reviewed 2026-11-13 against repository main `9703f3a6dafb674e7cd5cd00839ad3acbcbba384`.
Sources: Python [public exports](../../src/acr/sdk/__init__.py),
[client](../../src/acr/sdk/client.py), [errors](../../src/acr/sdk/errors.py),
[guards](../../src/acr/sdk/langgraph.py), and TypeScript [source](src/index.ts).

“Ported” means a corresponding public capability exists, not identical runtime
semantics or verified HTTP interoperability. “Missing” names a concrete gap;
“blocked” is reserved for a known external prerequisite (none identified here).
This inventory does not replace the working client or promise a port schedule.

| Python public export | Status | TypeScript counterpart / gap |
| --- | --- | --- |
| `ACRClient` | ported | `ACRClient` has registration, token, evaluation, health and readiness calls; all network methods are Promise-based, not synchronous. |
| `AsyncACRClient` | ported | The same Promise-based `ACRClient` serves async callers; no separate async class or Python context-manager/close lifecycle. |
| `ACRAgentSession` | ported | `ACRAgentSession` binds agent/token and supports evaluation and token refresh. |
| `AsyncACRAgentSession` | ported | `ACRAgentSession` methods return Promises; no separate async export. |
| `ACRSDKError` | missing | TS errors extend native `Error`; no common SDK-specific superclass shared by HTTP and decision errors. |
| `ACRHTTPError` | ported | `ACRHttpError` (different capitalization) retains `statusCode` and body; Python exposes `status_code`. |
| `ACRDecisionError` | ported | Retains the response; TS fallback uses nullish coalescing, so an empty-string reason stays empty unlike Python's truthiness fallback. |
| `ACRDeniedError` | ported | `assertRunnableDecision` throws it for `deny`; this does not itself wrap a tool. |
| `ACREscalatedError` | ported | Helper throws it for `escalate`, retaining approval metadata; no automatic resume. |
| `ActionRequest` | ported | Compile-time interface, not Python/Pydantic runtime validation or defaults. |
| `EvaluateRequest` | ported | Compile-time request interface including context and intent. |
| `EvaluateResponse` | ported | Decision and metadata fields represented; Python convenience properties `is_allowed`, `requires_approval`, `was_modified` are absent. |
| `IntentRequest` | ported | Compile-time interface with goal, justification, effects, step and metadata. |
| `guard_tool` | missing | No sync tool wrapper that evaluates first, blocks deny/escalate and applies modified arguments. |
| `guard_async_tool` | missing | No Promise-based equivalent of the Python async guarded execution wrapper. |
| `build_langchain_tool` | missing | No LangChain/LangGraph tool adapter or schema construction. |

## Scope and next gaps

- `assertRunnableDecision` is a TS-only convenience export, not a replacement for
  the missing guards. It returns the same allow/modify response; the caller must
  explicitly apply `modified_action` and invoke any local tool.
- Python validates gateway payloads through Pydantic. The TS client casts parsed
  bodies to interfaces and has no equivalent runtime response validation.
- This change tests the decision helper only. HTTP status handling, session
  refresh, transport failures and runtime payload validation need separate TS
  contract tests before claiming behavioral parity.
- Neither public SDK currently exports a dedicated approval-resume or durable
  execution-receipt client API. The gateway's newer endpoints are not evidence
  that either SDK exposes them. Do not treat this as a TS-only missing port.
- A future guard port should demonstrate all four decisions, exact modified
  arguments, zero side effects on deny/escalate, and no implicit execution after
  an approval reference is received. It would still be an application guard,
  not proof of a bypass-resistant execution boundary.
