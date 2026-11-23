# Auditor Guide

How an audit or GRC engagement runs against the ACR control plane
(v1.5.0 WS3). The auditor's access is **enforced, not conventional**: a
time-boxed, read-only grant, a decision explorer over the evidence
record, and an evidence package the auditor can verify without
installing or trusting ACR.

## 1. The grant

A `security_admin` issues the grant:

```
POST /acr/operator-keys/auditor-grants
{"name": "Q4 audit", "subject": "auditor@firm.example", "lifetime_hours": 168}
```

(or `"expires_at": "<ISO 8601 with timezone>"` instead of
`lifetime_hours` — exactly one of the two is required.)

Properties:

- Roles are forced to exactly `["auditor"]`. The grant cannot be issued
  wider, and there is no way to add roles to it afterwards.
- Expiry is mandatory and capped by `AUDITOR_GRANT_MAX_LIFETIME_DAYS`
  (default 30). An expired grant is rejected everywhere, including
  surfaces it could read the day before.
- Issuance and revocation are written to the operator audit log
  (actor, subject, key id, expiry). Revoke at any time:
  `POST /acr/operator-keys/{key_id}/revoke`.
- The plaintext key is shown once, at issuance. Store it like any other
  credential; only its SHA-256 is kept server-side.

The auditor authenticates with the `X-Operator-API-Key` header, the
same mechanism as other operator credentials.

## 2. What the grant can and cannot do

Enforcement is central, in the shared role dependency: an auditor-only
principal is rejected with 403 by **every non-GET route** (agent
registration and transitions, policy publish/activate, approval
decisions, operator-key management, containment actions, and the
gateway evaluate path), and by read surfaces outside the evidence
scope (operator-key management, policy drafts, drift administration).

In scope, read-only:

- Decision explorer: `GET /acr/decisions`, `GET /acr/decisions/chain/{id}`
- Agent manifests: `GET /acr/agents`, `GET /acr/agents/{id}`, lineage,
  observe reports
- Policy releases: `GET /acr/policy-drafts/releases/history`, active
  bundle download
- Approvals: `GET /acr/approvals`, `GET /acr/approvals/{id}` and its
  execution receipt
- Containment: `GET /acr/containment/status`
- Simulation reports: `GET /acr/policy-simulations/{run_id}` (+ summary)
- Telemetry: `GET /acr/events`, per-correlation evidence bundles

Every explorer read is logged with the reader's identity and the slice
read, so the audit itself leaves a trail.

## 3. The decision explorer

`GET /acr/decisions` filters by `agent_id`, `window_start` /
`window_end`, `decision`, `enforcement_mode`, `reason_contains`,
`tool_name`, and `correlation_id`, paginated with `limit` / `offset`,
newest first.

`GET /acr/decisions/chain/{identifier}` (a correlation_id, or a single
decision's id) returns the full chain for one action:

- the decision records, with their §18 sequence;
- the manifest snapshot **as evaluated** — present only when evaluation
  input retention (WS2) captured it; otherwise the link is reported
  absent, and the agent's current manifest is never silently
  substituted;
- the policy ids that decided, and the policy bundle identity when an
  approval's authorization snapshot carries one;
- the approval record and execution receipt, where they exist;
- the telemetry events for the correlation.

Every link carries a status (`present` / `absent`) and, when absent,
why. `missing_links` lists them in one place. An allowed call with no
approval is a fact; the chain states it rather than omitting the field.

The operator console carries the same surface (Decision Explorer tab):
filter list plus a chain viewer.

## 4. The evidence package

For a formal review, an operator generates a package for the window:

```
acr evidence-package --output evidence.zip \
  --window-start 2026-10-01T00:00:00Z --window-end 2026-11-01T00:00:00Z
```

or `POST /acr/evidence-packages` with the same window. Generation is an
operator action and is audit-logged (actor, window, chain head,
package hash).

Contents (see also `compliance/evidence-package.md`): summary
counts and rates, agent inventory and manifests, policy release
metadata, decision records (JSONL + CSV index), approvals, containment
events, drift samples, observe and simulation summaries, telemetry
integrity verdicts, and the framework control mapping embedded from
`docs/compliance/control-mapping.md`.

Two deliberate exclusions, stated in the package README:

- **Retained evaluation input payloads are never exported** — only
  their hashes and state. Retention redaction exists to protect those
  payloads; the package must not undo it.
- **Approval parameters are represented by SHA-256**, not value.

Release and deployment evidence (signed images, provenance, CI scan
output, deployment configuration) is not generated from runtime
records; it is supplied by the release process and listed as external
in the package README.

## 5. Verifying the package

The package contains `verify_package.py`, a standalone script using
only the Python standard library:

```
python3 verify_package.py [package-dir-or-zip]
```

It re-checks every file's SHA-256 against the hash-chained
`MANIFEST.json` (each entry carries the previous entry's hash, so
reordering, dropping, or editing an entry breaks the chain), confirms
no file is missing or smuggled in, and reconciles the summary counts
against the data files themselves. Exit code 0 means the package is
exactly what was generated; any tamper produces a specific error and a
non-zero exit.
