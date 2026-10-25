# How ACR Makes a Tool Decision

When an agent calls a guarded tool, the tool does not immediately run. The guard
sends the requested action to the ACR Gateway, which checks it and returns a
decision. Depending on that decision, the action may run, be blocked, be changed,
or wait for human approval.

The steps below describe the reference control plane's request flow. A
**guarded tool** is a tool wrapped by the ACR SDK so that it asks the gateway
for permission before calling the tool function. The **SDK**, or software
development kit, is the library an application uses to connect to ACR.

## Step 1: The agent asks to do something

### What it means

The guard sends the **ACR Gateway**—the service that checks tool-action
requests—the agent's identity, the tool name, its parameters (the values passed
to the tool), and any extra context. The gateway evaluates the request at its
`/acr/evaluate` address. A **correlation ID**—an identifier used to connect
records about this one request—is associated with the evaluation.

### Why it matters

The gateway sees the action before the guarded tool runs. A request is not
itself permission to perform that action.

### In plain English

The agent says, “I want to do this,” and ACR checks before the tool acts.

## Step 2: The gateway checks the token and agent state

### What it means

The request must include a valid **JSON Web Token (JWT)**, a signed credential
that identifies an agent. The agent ID in the token must match the ID in the
request. The gateway also checks whether a **kill switch**, an operator
controlled stop for an agent, has been activated and whether **graduated
containment** applies. Graduated containment is a
response that can limit an agent in stages: throttle its requests, restrict
which tools it can use, or make every action return an escalation decision.

### Why it matters

These checks help prevent an agent from acting as another agent or continuing
when it has been stopped or restricted.

### In plain English

ACR checks who is making the request and whether the agent is currently allowed
to proceed to the other checks.

## Step 3: ACR verifies the registered identity

### What it means

The gateway looks up the agent in the registry, the control plane's record of
registered agents. The agent must be registered, active, and in a lifecycle
state that permits action evaluation. The record also supplies the agent's
purpose, allowed tools, forbidden tools, and operating limits.

### Why it matters

The gateway needs an authoritative record of the agent's approved role and
boundaries; it does not rely only on what the request says about itself.

### In plain English

ACR checks that this is a known, active agent and loads the limits attached to
it.

## Step 4: ACR prepares rate and spend information

### What it means

The gateway supplies the policy check with a count, maintained by the gateway
itself, of the agent's actions in the current minute and its projected hourly
spend. A **policy** is a set of rules that governs which actions are allowed.
A **rate limit**
is a maximum number of actions allowed in a period. A **spend limit** is a
maximum allowed cost over a period. The gateway uses its own action counter,
not a count supplied by the agent. An active throttle can make the effective
action count reach the configured limit sooner.

These values are inputs to policy evaluation; gathering them is not, by itself,
the final decision. The policy can deny an action when a configured limit is
exceeded.

### Why it matters

Without limits, an agent could make too many calls or exceed its configured
spend boundary.

### In plain English

ACR checks how much the agent has been doing and spending, then gives those
figures to the rules that decide whether this action can continue.

## Step 5: Rego policies evaluate the action

### What it means

The gateway sends the agent record, requested action, and prepared context to
**Open Policy Agent (OPA)**, the policy service used by this implementation.
OPA evaluates rules written in **Rego**, its policy language. The rules can
allow or deny the action, request a change, or require approval. The included
shared rules check allowed and forbidden tools and apply rate and spend limits.
Other rules can set action-specific requirements, such as escalating a
high-value refund.

The gateway gives an explicit denial priority over escalation, then a valid
modification, then an allowance. Escalation or modification can therefore be
selected even without a separate allow result. If no applicable decision is
returned, the action is denied by default. A modification without a transformed
payload is also denied. If OPA is unavailable, the gateway fails securely
and does not treat the action as allowed.

### Why it matters

An agent's request is checked against the organization's rules, not just the
agent's own choice of tool.

### In plain English

The rules decide whether this agent may use this tool for this request, and
whether the request needs a change or a person's approval.

## Step 6: Sensitive values are redacted from parameters

### What it means

Before returning or executing the action, the gateway checks string values in
the action parameters for patterns matching several types of **personally
identifiable information (PII)**—information that can identify or contact a
person. The current filter recognizes patterns for social security numbers,
credit card numbers, email addresses, and phone numbers. Matching values are
replaced with `[REDACTED]`.

If the policy asked to modify the action, the gateway applies that policy's
transformed parameters before this filter. A policy cannot change the tool
name through a modify decision; an attempted tool-name change is denied. If
redaction changes an otherwise allowed request, the returned decision becomes
`modify`.

### Why it matters

The action can be adjusted to avoid passing recognized sensitive values
unchanged. This pattern-based filter is not a general-purpose detector for
every kind of sensitive information.

### In plain English

ACR removes certain recognizable personal details from the values being sent
with the tool action.

## Step 7: Risky actions can wait for human approval

### What it means

If policy evaluation returns `escalate`, the gateway creates an approval
request. **Escalation** means pausing the action and routing it to a human
approval workflow. The response includes an approval request ID, the approval
queue (the list where requests wait for review), and the configured review
time limit (the **SLA**, or service-level agreement, for the review).

The original tool action does not execute as part of this evaluation. It must
go through the approval workflow before it can proceed.

### Why it matters

Some actions are consequential enough that an automated rule should not make
the final decision alone.

### In plain English

ACR puts the action on hold and asks an authorized person to review it.

## Step 8: ACR records the outcome and returns the decision

### What it means

The gateway returns one of four decisions:

- **`allow`** — the action is permitted as requested.
- **`deny`** — the action is blocked and the guarded tool does not run.
- **`modify`** — the action is permitted only with the returned changed
  parameters.
- **`escalate`** — the action is waiting for human approval and does not run
  as part of this request.

For these policy outcomes, the gateway creates a **telemetry event**, a
structured record of something that happened in the control plane. It records
details such as the agent, tool, decision, policy results, filtering, and
correlation ID. The gateway emits a structured log and queues the event for
storage; the stored record includes **integrity information**, data used to
check whether the record has been changed. Events can be looked up by
correlation ID, and ACR's evidence-export feature can provide records for an
action.

When an allowed or modified action proceeds, the approved parameters are used
for execution. Depending on the integration settings, the guarded SDK calls
the local tool or uses the result from gateway-side execution. A denied or
escalated action does not call the local tool.

### Why it matters

The decision controls what happens next, and the associated record helps
operators understand and review what ACR decided.

### In plain English

ACR returns its answer, records the decision for later review, and only lets an
allowed action continue—with any required changes.
