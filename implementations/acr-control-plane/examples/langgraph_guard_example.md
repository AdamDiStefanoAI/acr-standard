# Runnable LangGraph guard example

This example compiles and invokes a real LangGraph `StateGraph` with a real
`ToolNode` and ACR-wrapped LangChain tools. It supplies deterministic `AIMessage`
tool calls instead of using a paid LLM. The tools mutate in-memory lists: no web
search or real email is sent.

## Install

> **Security limitation (2026-10-25):** the optional legacy LangChain/LangGraph
> dependency family below is **not audit-clean**. Do not install it for production
> evaluation pending a separately reviewed dependency migration. The SDK/base-package
> security fix does not remediate these optional dependencies. The base
> `pip install acr-control-plane` path does not install them. This command is
> retained only for isolated, disposable regression reproduction without secrets
> or untrusted inputs.

From `implementations/acr-control-plane/`, in your activated development virtual
environment:

```bash
python -m pip install -e '.[dev,integrations]' 'langgraph>=0.3,<0.7'
```

This example uses the repository's legacy LangChain Core 0.3 integration range.
The LangGraph bound keeps installation within the matching pre-1.0 framework
family; it is not a claim of compatibility with every newer LangGraph release.

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
