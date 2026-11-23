# Runnable LangGraph guard example

This example compiles and invokes a real LangGraph `StateGraph` with a real
`ToolNode` and ACR-wrapped LangChain tools. It supplies deterministic `AIMessage`
tool calls instead of using a paid LLM. The tools mutate in-memory lists: no web
search or real email is sent.

## Install

> **Verification status (2026-11-23, v1.5.0 WS5):** the guard and this
> example are verified against langchain-core 1.8.4 and langgraph 1.2.24;
> `pip-audit` reports no known vulnerabilities for this dependency family.
> (The 2026-10-25 not-audit-clean warning referred to the legacy pre-1.0
> family below and no longer applies.) The base
> `pip install acr-control-plane` path does not install them.

From `implementations/acr-control-plane/`, in your activated development virtual
environment:

```bash
python -m pip install -e '.[dev,integrations]' 'langgraph>=1.2,<2.0'
```

The `integrations` extra pins the verified LangChain Core 1.x line; the
LangGraph bound matches the release the WS5 verification pass ran against
(streaming, async dispatch, and retry paths included).

## Run with a local ACR gateway

Start a **disposable local** gateway following the
[sample agent setup](sample_agent/README.md). Keep `EXECUTE_ALLOWED_ACTIONS=false`
on that gateway: this example executes allowed tools locally and must not also
execute them remotely. Use the operator API key configured for your local gateway:

```bash
export ACR_BASE_URL=http://localhost:8000
export ACR_OPERATOR_API_KEY='<your-local-operator-key>'
python examples/langgraph_guard_example.py
```

The script registers `langgraph-guard-demo`, obtains an agent session, files one
report, and attempts one forbidden external email. It prints `filed: ACR demo`,
a denial reason, and `Side effects: reports=1, external_emails=0`. A changed or
pre-existing agent policy can change the outcome; the script fails rather than
claiming success when the expected denial or side effects are absent.

`ToolNode(..., handle_tool_errors=False)` deliberately propagates `ACRDeniedError`
and `ACREscalatedError` to the application. Applications can catch those errors to
choose their own stop/approval workflow. An escalation does not automatically
resume a graph after approval.

## Offline regression check

```bash
ACR_ENV=test python -m pytest tests/test_langgraph_example.py -v
```

These four cases run actual compiled graph dispatch through the SDK's HTTP
serialization and decision handling, for synchronous `invoke` and asynchronous
`ainvoke`, with denial returned as either HTTP 200 or HTTP 403. They verify the
allowed tool's list mutation and returned `ToolMessage`, and that the denied
tool never mutates its list. Only ACR's HTTP responses are synthetic
(`httpx.MockTransport`); no gateway, database, Redis, OPA, LLM, or credentials are
needed. These are framework integration regressions, **not** live-stack policy
or authentication validation. Without LangGraph installed, this optional test
module is skipped; install the dependencies above to actually run it.

A local wrapper is cooperative enforcement, not proof against bypass by code
that still has direct downstream access. See the
[protected executor example](protected_executor/README.md) for the separate
execution boundary and its limitations.

Framework reference: [LangGraph Graph API](https://docs.langchain.com/oss/python/langgraph/graph-api).
