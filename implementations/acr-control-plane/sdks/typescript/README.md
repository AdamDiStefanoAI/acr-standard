# ACR TypeScript SDK

This package provides the official TypeScript client for the ACR control plane.

## What It Covers

- operator-side agent registration
- token issuance
- runtime calls to `POST /acr/evaluate`
- session-bound agent helpers
- decision-aware error helpers

## Install

```bash
npm install acr-control-plane-sdk
```

## Basic Usage

```ts
import { ACRClient } from "acr-control-plane-sdk";

const client = new ACRClient({
  baseUrl: "https://acr.example.com",
  operatorApiKey: process.env.ACR_OPERATOR_API_KEY!,
});

await client.ensureAgentRegistered({
  agent_id: "support-bot",
  owner: "support@example.com",
  purpose: "Handle support actions",
  risk_tier: "medium",
  allowed_tools: ["query_customer_db", "send_email"],
});

const session = await client.issueAgentSession("support-bot");

const result = await session.evaluateAction({
  tool_name: "send_email",
  parameters: {
    to: "alice@example.com",
    subject: "Ticket update",
    body: "We resolved your issue."
  },
  description: "Send support resolution email"
}, {
  session_id: "sess-123"
});

console.log(result.decision);
```

## Decision Handling

The SDK returns normal decision payloads for:

- `allow`
- `modify`
- `deny`
- `escalate`

If you want exception-based control flow, use `assertRunnableDecision(result)`.

## Package Layout

- [src/index.ts](src/index.ts): source SDK
- [dist/index.js](dist/index.js): runtime JS entrypoint
- [dist/index.d.ts](dist/index.d.ts): published TypeScript declarations

### Service-free example and tests

From this directory, using Node 18 or newer:

```bash
npm ci
npm run typecheck
npm test
node examples/decision-handling.mjs
```

The pinned local TypeScript compiler and lockfile avoid a global compiler
requirement. `npm test` rebuilds `dist` from source before running Node's built-in
test runner. Tests and the [runnable example](examples/decision-handling.mjs)
use synthetic decisions, make no HTTP requests, and need no credentials or ACR
services. Dependency installation requires access to the npm registry.

```js
import {
  assertRunnableDecision, ACRDeniedError, ACREscalatedError,
} from './dist/index.js';

const responses = [
  { decision: 'allow' },
  { decision: 'modify', modified_action: { tool_name: 'refund', parameters: { amount: 25 } } },
  { decision: 'deny', reason: 'Refund forbidden by synthetic policy' },
  { decision: 'escalate', reason: 'Human approval required', approval_request_id: 'synthetic-approval-001' },
];
for (const response of responses) {
  try {
    const runnable = assertRunnableDecision(response);
    console.log(runnable.decision, runnable.modified_action);
  } catch (error) {
    if (error instanceof ACRDeniedError) console.log('No execution:', error.message);
    else if (error instanceof ACREscalatedError) console.log('Wait:', error.response.approval_request_id);
    else throw error;
  }
}
```

The helper checks whether a decision is runnable; it neither executes tools nor
applies modifications. For `modify`, callers must execute the returned
`modified_action` with its modified parameters, not the original request. The
runnable example shows this selection and refuses a missing modified action.
A synthetic approval ID is only a demonstration: escalation does not authorize
execution, and this example does not resume an approved action.

See [PARITY.md](PARITY.md) for the Python SDK comparison and known gaps.
