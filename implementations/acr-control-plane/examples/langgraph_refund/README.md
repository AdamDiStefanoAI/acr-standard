# Offline LangGraph refund example

A real compiled `StateGraph` calls the existing `guard_tool` wrapper around a
fake `issue_refund`. The real ACR SDK serializes the evaluation request, while
`httpx.MockTransport` supplies deterministic allow, deny, and escalate responses.
The only refund effect is appending an amount to a Python list. No money moves.

## Install and run

**Security limitation:** this optional legacy LangGraph/LangChain family is not
claimed audit-clean. As with the [existing graph example](../langgraph_guard_example.md),
use an isolated, disposable environment with no secrets or untrusted inputs.
Do not install these example dependencies for production evaluation. They do not
change the base package's dependencies or remediate optional-framework advisories.

From `implementations/acr-control-plane/`, using Python 3.11 or 3.12:

```bash
python -m venv .venv-refund
source .venv-refund/bin/activate
python -m pip install -e '.[dev,integrations]' -r examples/langgraph_refund/requirements.txt
python examples/langgraph_refund/agent.py
python -m pytest tests/test_langgraph_refund_example.py -q
```

The optional requirements pin LangGraph 0.6.11 and LangChain Core 0.3.83 within
the project's legacy integration range. LangGraph is not included in the
`integrations` extra, so the separate requirements file is necessary. Without
LangGraph installed, these optional tests skip rather than validate the example.

Validated in a fresh environment on 2026-11-13 with Python 3.12.14,
LangGraph 0.6.11, LangChain Core 0.3.83, HTTPX 0.28.1, and pytest 9.2.0:
the example ran as shown, all five refund tests passed, and `pip check` found
no dependency conflicts. This is functional compatibility evidence, not a
security audit.

Expected output:

```text
allow: fake_refund_calls=1; result={'status': 'simulated', 'amount': 125.0}
deny: fake_refund_calls=0; result=simulated deny
  handled ACRDeniedError
escalate: fake_refund_calls=0; result=simulated escalate
  handled ACREscalatedError
  approval_request_id=synthetic-refund-approval-001
```

After installation, no credentials, network, LLM, database, Redis, OPA server,
or Docker are required. The token and approval ID are synthetic. Unexpected HTTP
requests fail assertions and cannot fall back to a live transport. Tests verify
one evaluation per scenario and authorization before any list mutation.

## What this proves, and what it does not

Allow executes the fake tool exactly once; deny and escalate propagate their
SDK exceptions out of the graph and execute it zero times. The caller handles
those exceptions visibly. Escalation stops execution: this example creates no
real approval queue item and does not resume automatically.

**Policy decisions are simulated**, not evaluated by a running ACR gateway.
This is integration regression coverage, not authentication, live policy, payment,
or production security validation. A local cooperative wrapper does not establish
a bypass-resistant execution boundary when code can call downstream systems
directly. See the [protected executor](../protected_executor/README.md) for that
separate boundary and its limitations.
