# Safe approval resumption and execution receipts

## First increment and pass/fail scenario

An agent requests a refund, policy escalates it, and an authorized human approves
that exact action. Before execution, permissions may be revoked, containment may
change, policy may be activated, the approval may expire, or the payload may be
altered. **Pass:** execution does not occur under any of those conditions. A new
action evaluation and approval is required for changed authorization/payload.

A second scenario executes the fixture refund, but its response is lost.
**Pass:** a repeat request does not issue another refund. The receipt remains
unknown and requires downstream reconciliation. Successful repeats return the
stored outcome. This is an at-most-one dispatch fence per approval, not an
exactly-once guarantee for external systems or separately submitted actions.

## Enforcement

New escalation requests store a canonical hash of the execution envelope,
queue, expiry and request context, plus a snapshot of the agent manifest,
containment and evaluated core/operator/Studio policy identity. All active Studio
releases are included conservatively: changing another agent's active release
also invalidates the snapshot. This trades availability for an unambiguous
configuration boundary. The actual OPA response must match the active database
configuration both at escalation and resumption, so asynchronous bundle polling
cannot silently resume against a stale Studio policy.

Approve/override check expiry and request integrity. Execution checks the
recorded human decision, current agent lifecycle, kill/restrict/isolate/throttle
state, current manifest, active policy identity, authoritative rate/projected
spend inputs, fresh OPA decision, approval queue, and output filtering. A new
MODIFY result is not automatically accepted. Break-glass approval cannot bypass
these checks. Redis/OPA/receipt-storage failure does not permit dispatch.

After committing the dispatch claim, the gateway re-reads the record, agent,
containment and policy identity immediately before dispatch. This also checks
expiry across a slow policy evaluation/commit. There is no atomic transaction
spanning PostgreSQL, Redis, OPA and a remote executor: revocation concurrent with
the final send still requires downstream enforcement. No resource-version or
business-state verifier is supplied in this increment. Original client context
is retained, not treated as freshly verified external resource state.

## API and durable states

- Existing `POST /acr/approvals/{id}/approve` and `/override` dispatch when
  execution is enabled, with fresh checks. Approval responses remain compatible.
- `POST /acr/approvals/{id}/execute` resumes a recorded approval, using a freshly
  authenticated approver/security-admin caller. It never bypasses the checks and
  is disabled when downstream execution is disabled. It also retrieves a prior
  successful outcome without another dispatch. Original approver history is
  retained; this does not introspect historical IdP membership of that person.
- `GET /acr/approvals/{id}/receipt` is restricted to approvers, auditors and
  security administrators. It exposes the dispatch attempt, frozen approved
  envelope/context, policy/identity evidence, decision and executor outcome.
- `executing`: committed dispatch fence; the process may still be running or
  may have died before/during/after a send. Never reclaim or automatically retry.
- `succeeded`: executor returned an object and its result was committed. This is
  the executor's reported outcome, not independent proof of a business effect.
- `unknown`: dispatch failed or response was uncertain; do not retry.
- `blocked`: a post-claim authorization/dependency check failed before dispatch;
  no executor was called. Reevaluate and obtain a new approval if appropriate.

The receipt is inserted and committed before any executor call. Its unique
approval key fences concurrent callers even if both pass authorization checks.
A failure to commit the claim prevents execution. If the external action succeeds
but final evidence persistence fails, the committed `executing` fence remains.
Receipts have no cascading agent/approval foreign key so deletion cannot erase
this evidence. The snapshot includes the frozen action for traceability even if
the original approval disappears. Consequently receipt access, backups and
retention must protect potentially sensitive request/result data. These rows
are not a cryptographically signed or tamper-proof audit archive.

## Recovery and limits

Use the approval/correlation ID, receipt and downstream service logs to determine
whether an unknown/executing attempt occurred. There is intentionally no API to
clear a claim, retry an unknown outcome, or assert success without evidence.
Operator-led reconciliation and integration-specific lookup are required. A
second, separately evaluated request has a different approval key; it is not
business-level deduplication. The existing executor idempotency header is useful
only when the downstream implementation actually honors it.

Estimated spend is retained on blocked/uncertain outcomes conservatively. Shared
budget reservation across distinct concurrent actions is not atomic in the
existing spend ledger; this increment does not claim to solve it. Rate counters
can count refused/repeated attempts. Receipt coverage here is approval execution,
not the separate immediate ALLOW/MODIFY path or all SDK executors.

## Migration and validation

Run Alembic migration 0014. Legacy requests remain unbound and cannot be resumed;
deny and resubmit them rather than attaching today's policy to yesterday's
approval. Update/reload OPA bundles to include the Studio identity marker.

Focused safe-fixture tests are in `test_safe_approval_resume.py`,
`test_execution_receipts.py` and `test_approval_policy_identity.py`. They cover
payload/context/queue mutation, expiry, revocation, containment changes, stale
policy, denial/modification, dependency failure, durable success/replay,
response loss, unfinished claims, storage failure, and concurrent claims.
Run from the implementation directory with the supported OPA 0.70 executable:

```sh
ACR_ENV=test python -m pytest tests/ --ignore=tests/integration
ruff check src tests
```

Tests use local fixture actions, not real refunds, emails or production accounts.
PostgreSQL migration/runtime and deployed executor testing remain distinct
release gates; unit tests alone do not establish production readiness.
