# Benchmarks — the evaluate path, measured

*v1.5.0 WS6 (the numbers pack). Companion: `scripts/benchmark_harness.py`,
`.github/workflows/acr-benchmark.yml`, `benchmarks/results-2026-11-23.json`.*

Every ACR evaluation is synchronous evidence: the policy decision is
evaluated and durably recorded **before** the response returns and before
any approved action executes (§18). That design has a price, and this
document states it in numbers instead of adjectives — what the measured
path costs, what dominates the cost, and what the numbers do *not* claim.

## Methodology

- **Harness.** `scripts/benchmark_harness.py` (Python standard library
  only), run against a live gateway. Same operating pattern as the
  red-team harness: register disposable agents, issue one agent JWT per
  agent, measure, verify.
- **Load model.** Closed loop: a fixed number of worker threads, each
  with its own keep-alive HTTP connection, issuing requests
  sequentially with no think time. 25 warmup requests per stage are
  discarded; 200 measured requests per (workload, concurrency) stage.
- **Percentiles.** Nearest-rank over client-observed end-to-end latency
  (request sent → full response read), reported as p50/p95/p99, plus
  achieved throughput over the stage's wall time.
- **Workloads.** One fixed request shape and one dedicated agent per
  workload, so drift baselines, rate limits, and spend counters never
  interact across workloads. Agent boundaries are set non-binding
  (the rate-limit and spend controls still execute on every call; the
  benchmark measures the path, not the limiter).
  - `allow` — `query_customer_db`, benign parameters → allow (200).
  - `deny` — `send_email` carrying an SSN in the body → deny (403)
    under the shipped customer-support policy set.
  - `escalate` — `issue_refund` of $250 → escalate (202), approval
    request created in the finance-approvals queue.
  - `observe_allow` / `observe_deny` — the allow/deny probes against an
    agent in WS1 observe mode (HTTP 200, `would_be_decision` verified),
    for the observe-mode overhead delta.
- **Decision verification.** Every response's decision is checked
  against the workload's expected decision (and `would_be_decision` for
  observe workloads). A run whose decisions do not match is a failed
  run (harness exit 3) and its numbers are discarded, never averaged
  in. This is not ceremony: during preparation of this document an
  early run *was* invalidated this way — the host ran out of disk,
  Postgres stopped, evaluations failed secure (deny / 503), and the
  verification rejected the run.
- **What is not measured.** Downstream tool execution
  (`EXECUTE_ALLOWED_ACTIONS` is off), approval *resolution* (the
  escalate workload measures creating the approval request, not a human
  deciding), the operator console, the MCP gateway proxy hop, and any
  topology other than the one under test.

## Published run — 2026-11-23

Environment, stated plainly because the numbers are meaningless without
it: **a single small sandbox VM** (AMD EPYC 9D25, ≈1.5 shared vCPU,
throttled; 6 GiB RAM) with *everything co-located on one host* — gateway
(uvicorn, 2 workers, the compose default), OPA 0.70.0, PostgreSQL 16.2
(schema at Alembic head 0022), Redis 6.2.14, and the load generator
itself, all on loopback. Policies: the managed core plus the shipped
operator extension (`operator-policies/customer_support.rego`). This is
a floor, not a showcase: the generator competes with the stack for the
same ≈1.5 vCPU. Full data: `benchmarks/results-2026-11-23.json`.

| Workload | Concurrency | p50 (ms) | p95 (ms) | p99 (ms) | Throughput (req/s) |
|---|---|---|---|---|---|
| allow | 1 | 27.1 | 54.5 | 88.5 | 32.0 |
| allow | 4 | 106.3 | 188.0 | 278.0 | 34.2 |
| allow | 8 | 217.4 | 309.1 | 369.1 | 33.8 |
| deny | 1 | 32.3 | 54.5 | 68.6 | 28.3 |
| deny | 4 | 103.3 | 207.8 | 247.7 | 29.8 |
| deny | 8 | 284.7 | 412.0 | 464.5 | 27.5 |
| escalate | 1 | 37.8 | 52.8 | 73.8 | 24.7 |
| escalate | 4 | 123.2 | 194.5 | 215.5 | 29.3 |
| escalate | 8 | 270.5 | 366.9 | 414.8 | 29.4 |
| observe_allow | 1 | 27.7 | 46.3 | 68.9 | 32.2 |
| observe_deny | 1 | 30.2 | 48.9 | 66.5 | 30.3 |
| observe_allow | 8 | 217.2 | 356.6 | 408.7 | 33.3 |
| observe_deny | 8 | 232.0 | 442.3 | 552.2 | 29.8 |

### How to read this

- **The single-threaded cost of synchronous evidence is ~27–38 ms
  (p50)** on this host, escalations highest (an approval request row is
  written in addition to the decision record). On production hardware
  with dedicated cores, expect materially lower numbers; re-run the
  harness there rather than extrapolating these.
- **Throughput saturates at ≈25–39 req/s at every concurrency level.**
  That is a host CPU ceiling, not a measured product ceiling: latency
  grows ~linearly with concurrency past saturation, the classic
  queueing signature of a saturated shared resource. The honest claim
  is "at least this fast on a ≈1.5-vCPU shared sandbox"; the harness
  exists so the claim on *your* topology is measured, not asserted.
- **Observe mode costs nothing measurable.** At concurrency 1 the
  observe delta is +0.5 ms (allow) and −2.1 ms (deny) against the
  enforce figures — inside run-to-run noise (±6% at p50 between the
  two same-day runs). That is the design working as intended: observe
  still evaluates and records synchronously; what it skips (execution,
  approval creation) is outside the measured path.

## What dominates the budget

Per evaluation, in order: (1) the §18 recording write — a Postgres
transaction that assigns the per-agent sequence and persists the
decision record (plus an approval row on escalate, plus a retained
input row when WS2 retention is on); (2) the OPA evaluation round
trip; (3) Redis reads/writes (kill-switch state, rate-limit and spend
counters, containment); (4) the drift check, which runs on every
evaluation by default (`DRIFT_CHECK_EVERY_N=1`). Gateway CPU (request
handling, output filtering) is the remainder. The two-pool database
design (hot path 25 + 25 overflow; background 10 + 10) exists so
telemetry and drift background work cannot starve the recording write.

## Tuning levers

- **Gateway workers / replicas.** `WEB_CONCURRENCY` per container, or
  more gateway replicas (see `docs/high-availability.md`). On a
  CPU-bound host this is the first lever; the sandbox run above is
  worker-starved by construction.
- **Postgres.** The recording write is the floor of the budget: keep
  Postgres on fast local storage, and use PgBouncer (transaction
  pooling) before raising replica counts — each gateway replica can
  open up to 70 connections across its two pools.
- **OPA placement.** OPA is a separate process by design; co-locating
  it with the gateway (same host/pod, as in the compose stack and the
  k8s base) keeps the evaluation round trip on loopback.
- **`DRIFT_CHECK_EVERY_N`.** Raising it trades drift-detection latency
  for evaluate latency. The default (every evaluation) is the safe
  posture; the v1.4.0 history shows why sampled drift misses slow
  deviations.
- **WS2 input retention** adds one write per evaluation when enabled.
  It is off by default; enabling it is a policy decision with a known,
  measurable cost — measure with the harness before and after.

## Reproducing

Against any running stack (compose or otherwise):

```bash
cd implementations/acr-control-plane
GATEWAY_URL=http://127.0.0.1:8000 OPERATOR_API_KEY=<operator key> \
  python3 scripts/benchmark_harness.py \
  --concurrency 1,4,8 \
  --output benchmarks/results-<date>.json \
  --markdown benchmarks/results-<date>.md
```

Or dispatch `.github/workflows/acr-benchmark.yml` manually; it boots
the disposable full-stack, runs the harness, and uploads the results
files as artifacts.

**Tolerance.** On hardware equivalent to the published environment, a
reproduction should land within ±25% of the published p50 figures;
the two same-day runs here agreed within ~6% at concurrency 1. A
reproduction on different hardware is a *new* published number for
that topology, not a discrepancy — file it as its own results file
with its own environment block. A run that fails decision
verification is not a slower run; it is a broken stack, and the
correct response is to fix the stack, not to publish the numbers.
