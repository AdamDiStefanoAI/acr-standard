# Policy simulation: replay real traffic before you promote a policy

Policy simulation answers the change-control question — *"what would this
bundle have done to our actual traffic?"* — before a policy change is
promoted. It replays recorded evaluations against a candidate Policy
Studio bundle, offline, and diffs the simulated decisions against the
decisions that were actually issued.

## Retention: the privacy posture comes first

Simulation needs real evaluation inputs, and real inputs are real
payloads. So retention is **off by default** and opt-in per deployment:

| Setting | Default | Meaning |
| --- | --- | --- |
| `EVALUATION_INPUT_RETENTION_ENABLED` | `false` | Master switch. Off means nothing is stored and the evaluate path is unchanged. |
| `EVALUATION_INPUT_RETENTION_DAYS` | `30` | How long a retained input is kept before its payload is purged. |
| `EVALUATION_INPUT_REDACTION_FIELDS_JSON` | `""` (none) | JSON array of dot-paths into the evaluation input whose values are redacted before storage, e.g. `["action.parameters.customer_id", "context.api_key"]`. |
| `EVALUATION_INPUT_PURGE_INTERVAL_SECONDS` | `3600` | How often the background purge loop runs. |
| `POLICY_SIMULATION_GATE_ENABLED` | `true` | The promotion gate described below. Only binds while retention is on. |

What is retained is the **effective evaluation input** — the exact agent
manifest, action, and enriched context handed to the policy engine —
because that is what a faithful replay needs. The raw HTTP request is
not enough (the engine also sees server-side counters).

The rules that keep this safe:

1. **Redaction happens before storage.** Configured fields are replaced
   with the fixed marker `[REDACTED]` in a copy of the payload; the
   unredacted payload never reaches the database. Simulation reports
   and exports read only the stored, already-redacted copy — nothing
   downstream can re-derive an unredacted value because it exists
   nowhere.
2. **Retention is bounded.** Every retained input carries an expiry.
   A background loop (and `acr purge-evaluation-inputs`) deletes expired
   payloads. The decision records are never deleted; the retention row
   remains as a tombstone noting the input was retained and purged,
   which is what keeps coverage reporting honest (below).
3. **Retention rides the decision-recording transaction.** The retained
   input commits — or rolls back — with the evaluation's decision
   records. If input storage fails, the recording fails exactly like a
   decision-write failure and the evaluation fails secure with the
   existing 503 `EVIDENCE_PERSISTENCE_FAILED` path. Retention can never
   produce a decision without its evidence, or evidence for a decision
   that was never recorded.

Choose redaction fields for the payloads your agents actually carry:
customer identifiers, credentials in context, free-text fields that may
contain personal data. If a field is not listed, it is stored as-is —
treat the retention table as sensitive and scope database access
accordingly.

## Running a simulation

Against a candidate release (a published Policy Studio release that has
not necessarily been activated):

```bash
acr simulate \
  --release-id rel-0123abcd \
  --window-start 2026-11-16T00:00:00Z \
  --window-end   2026-11-23T00:00:00Z
```

or via the operator API (running requires the `security_admin` role;
`agent_admin` and `auditor` can read reports):

```http
POST /acr/policy-simulations
{"release_id": "rel-0123abcd",
 "window_start": "2026-11-16T00:00:00Z",
 "window_end": "2026-11-23T00:00:00Z"}

GET /acr/policy-simulations/{run_id}            → JSON report
GET /acr/policy-simulations/{run_id}/summary.md → Markdown summary
```

A simulation is fully offline: it evaluates the candidate bundle with
the local OPA binary and writes nothing except its own run record. It
creates no approvals, emits no live telemetry, and never touches the
decision records it replays against. Every run is stored durably with
the actor, the exact bundle hash, the window, and a result hash over
the report's substantive content.

## Reading the report

- **Coverage first.** `decisions_in_window` is how many evaluations the
  window contains; `inputs_available` is how many could actually be
  replayed; `inputs_missing` is the gap — inputs that were never
  retained (retention was off) or have since been purged. A report with
  a gap says so, in numbers, and does not speak for the missing
  evaluations. If the gap matters, narrow the window to a fully
  retained period.
- **Flips by direction** (`allow->deny`, `deny->allow`,
  `allow->escalate`, …) are the headline. A `deny->allow` flip is a
  control being *removed* — read those first.
- **Flips by deciding rule** groups flips by the simulated outcome's
  deciding rule (the deny reason for denials — that is what the engine
  exposes).
- **Sample flipped cases** (up to 20) show the stored — redacted —
  input with its recorded and simulated decisions, so a reviewer can
  judge whether each flip is the change they intended.

Zero flips against the currently shipping bundle is the expected
sanity result: replay uses the same decision-derivation rules as the
live path, so a faithful window reproduces recorded decisions exactly.

## The promotion gate

While retention is on (and `POLICY_SIMULATION_GATE_ENABLED` is on,
the default), **activating a managed release requires a simulation
report for the exact bundle being activated**:

```http
POST /acr/policy-drafts/releases/{release_id}/activate
{"simulation_report_id": "sim-…"}
```

Activation is the promotion step — it is what distributes the bundle —
so that is where the gate sits. Publishing a draft into a release stays
inert. The gate compares the report's bundle SHA-256 against the bundle
the activation would distribute; a report for any other bundle (an
older draft, another agent's policy) is rejected. The release records
the report it was activated under (`simulation_report_id`), and the
activation is audit-logged with the actor and report id.

When retention is off, the gate is inert and activation behaves exactly
as it did before simulation existed — there is no retained traffic to
simulate against, so requiring a report would be theater.

## A sane change workflow

1. Turn retention on for the deployment, with redaction fields set,
   and let real traffic accumulate.
2. Draft the policy change; publish it as a release.
3. Simulate the release over a representative, fully covered window.
4. Read the flips. Every `deny->allow` and every unexpected flip gets
   an explanation before promotion.
5. Activate with the simulation report id attached. The report, the
   bundle hash, and the activation are all in the evidence trail.
