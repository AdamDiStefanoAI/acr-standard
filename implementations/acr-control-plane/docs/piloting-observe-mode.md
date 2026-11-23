# Piloting with Observe Mode

Observe mode exists for one reason: no enterprise should have to turn on
fail-closed enforcement against production agent traffic on faith. An
agent in `observe` mode runs the identical policy evaluation as an
enforcing agent, every decision is recorded with the same synchronous
§18 evidence semantics, and then the call proceeds anyway. What you get
back is the truth about what enforcement *would* do to your real
traffic, with zero production risk. What you do with that truth is this
guide: a 30-day pilot, per agent.

## What observe mode is — and is not

- The evaluation is not a simulation. The full policy stack runs, the
  decision is assigned its sequence position and durably recorded
  before the response returns, and if the decision cannot be recorded
  the evaluation fails secure with a 503, exactly as in enforce mode.
  Observe mode gets no exception to the evidence rules.
- The recorded decision is the **would-be decision**: `allow`, `deny`,
  `modify`, or `escalate`, stamped `enforcement_mode: "observe"` on the
  decision record and the telemetry event. Reports never mix modes.
- The evaluate response is non-blocking: HTTP 200, `decision: "allow"`
  (the effective outcome), `enforcement_mode: "observe"`,
  `would_be_decision` carrying the verdict, `enforced: false`. Your
  SDK/guard can log the would-be decision on the caller side.
- No approval request is created for a would-be escalation, and a
  would-be modification is **not** applied: the agent's requested action
  proceeds, with only the standing output-filter redaction applied to
  its parameters (the filter is a data control and applies in both
  modes).
- **Containment is exempt.** The kill switch and graduated containment
  (throttle / restrict / isolate) run before mode is read and apply to
  observe-mode agents exactly as to enforcing ones. Observe is a policy
  pilot, not a containment holiday.

## Mode is operator state, nothing else

Enforcement mode lives only on the stored agent record. It is set at
registration or changed through one dedicated endpoint:

```
POST /acr/agents/{agent_id}/enforcement-mode
{"target_mode": "observe", "reason": "30-day pilot"}
```

The endpoint requires an operator principal with the `agent_admin` or
`security_admin` role, and every transition is written to the audit
trail with the actor, the from/to modes, and the operator-supplied
reason. The generic agent update endpoint deliberately does not carry
the field. Nothing in an evaluate request — headers, body fields,
context, parameters, tool names — can influence mode; red-team category
2 exists to keep proving that.

## The 30-day pilot

**Days 0–1 — Register in observe.** Register the agent with
`enforcement_mode: "observe"` (or transition an existing agent), pointed
at real traffic through your SDK guard. Confirm decisions are landing:
the observe report should start filling within the first calls.

**Days 2–27 — Let it run.** Do not tune policy on day-two data. You are
collecting the distribution of what enforcement would do to ordinary
traffic, including the boring weeks, not just the incidents.

**Days 28–30 — Read the report.**

```
GET /acr/agents/{agent_id}/observe-report
GET /acr/agents/{agent_id}/observe-report?window_start=...&window_end=...
```

The report aggregates only that agent's observe-mode decisions over the
window (default: the last 30 days): counts by would-be decision, the
tools that would have been blocked most (deny + escalate, broken out),
and sample decision references (correlation ID, sequence, tool, reason)
for spot-checking individual calls against your own logs.

Read it in this order:

1. **Would-be deny rate.** High is not bad; unexplained is. Sample the
   decision references and classify each: true positive (the call
   should never run), policy gap (the policy is wrong for this agent),
   or agent bug (the agent is asking for things it should not).
2. **Top blocked tools.** This is your promotion risk list. A tool that
   would be denied 400 times a day is either misconfigured policy or a
   workflow that depends on access it should not have. Resolve which
   before promotion, per tool.
3. **Would-be escalations.** Each one is a future approval queue item.
   Check the volume against your approvers' capacity and the SLA you
   intend to run; an unstaffable queue is a policy problem, not a
   staffing one.

**Tune, then re-observe what changed.** Policy fixes go through Policy
Studio like any other change. If you changed rules materially, give the
changed rules a few more observe days; the report window parameters let
you compare before/after cleanly.

**Promote per agent.** Promotion is the transition endpoint with
`target_mode: "enforce"` and a reason that references the report you
read. Promote one agent at a time, starting with the agent whose
would-be deny list you fully explained. Stepping back is the same call
in reverse; nothing about promotion is one-way.

Approvals already queued when you flip modes keep the semantics they
were issued under — a flip neither approves, denies, nor orphans them.

## What a good pilot produces

- A would-be deny list where every sampled item is explained.
- A blocked-tool list with an owner and a disposition per tool.
- An escalation volume your approvers have seen and accepted.
- A promotion decision a skeptic can audit: the report, the window,
  and the transition record with its reason, all in the evidence trail.
