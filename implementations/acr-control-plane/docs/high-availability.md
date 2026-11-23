# High availability — reference topology and runbook

*v1.5.0 WS6 (the numbers pack). Complements `docs/deployment.md` and
`docs/production_install.md`; this document is the HA-shaped reading of
the same material, with an explicit line between what is **proven** by
automated validation and what is **documented but unproven**.*

The control plane's availability story is constrained by its safety
story: the evaluate path fails **closed**. A dependency outage does not
degrade ACR into a pass-through; it denies. HA here is therefore not
about keeping a convenience up — it is about keeping the *enforcement
point* up, because while it is down, governed agents stop.

## Reference topology

```
                    ┌───────────── ingress / LB ─────────────┐
                    │              (TLS, sticky not required) │
              ┌─────┴─────┐                          ┌───────┴───┐
              │ gateway-0 │  uvicorn workers         │ gateway-1 │  …
              │ OPA poll  │  per replica             │ OPA poll  │
              └─────┬─────┘                          └───────┬───┘
                    │        ┌───────────────┐             │
                    ├────────┤  OPA (per-pod  ├─────────────┤
                    │        │  or shared)   │             │
              ┌─────┴────────┴──────┐  ┌─────┴─────────────┴───┐
              │ Postgres (HA)       │  │ Redis (HA endpoint)   │
              │ via PgBouncer       │  │ kill state, counters, │
              │ §18 records, grants │  │ containment, drift    │
              └─────────────────────┘  └───────────────────────┘
              killswitch service (separate deployment, ≥1 replica;
              state lives in Redis, actions — not reads — need it)
```

- **Gateway replicas ≥ 2.** The k8s base ships `replicas: 2`, an HPA,
  and PodDisruptionBudgets (`deploy/k8s/base/`). Gateway state is
  externalized by design: sessions, decisions, and approvals live in
  Postgres/Redis, so any replica can serve any request and replicas
  are interchangeable. The production overlay
  (`deploy/k8s/overlays/production/`) adds ExternalSecrets-managed
  credentials and production network policies.
- **OPA.** Each gateway replica polls the managed bundle from the
  gateway bundle endpoint (any replica can serve it; the bundle is
  built from the active policy releases in Postgres). Run OPA as a
  per-pod sidecar or a small shared deployment; keep it on loopback or
  same-node networking — the evaluation round trip is in the latency
  budget (`docs/benchmarks.md`). If OPA is unreachable, the policy
  client's circuit breaker opens and evaluations fail secure.
- **Postgres.** The system of record: §18 decision records, approvals,
  auditor grants, policy releases, the integration outbox. Run it as a
  managed HA instance (multi-AZ or equivalent) or a Patroni-style
  self-managed cluster. **Put PgBouncer (transaction pooling) in front
  before scaling replicas**: each gateway replica configures two pools
  (hot path 25 + 25 overflow; background 10 + 10), so N replicas can
  present up to 70 × N connections. Backup and restore follow
  `docs/deployment.md` § Backup; decision records are evidence and
  should be in the backup scope from day one.
- **Redis.** Hot-path state: kill-switch reads (every evaluation),
  rate-limit and spend counters, graduated containment, token-issuance
  limits. The gateway takes a **single Redis endpoint**
  (`REDIS_URL`); this release does not wire Redis Sentinel or Cluster
  clients. For HA, present one highly-available endpoint in front of
  Redis — a managed HA Redis, or a Sentinel-managed pair fronted by a
  proxy/virtual IP — and treat that layer as part of *your*
  infrastructure, tested by you. The failure semantics are
  deliberately unforgiving: with Redis unreachable and no degraded
  opt-in, kill-switch reads raise and evaluations fail secure, and
  token issuance fails closed with 503. `ALLOW_DEGRADED_DEPENDENCIES`
  exists for development/test only and startup refuses it elsewhere
  (v1.4.0 posture). Losing Redis therefore means governed agents stop,
  by design; size and monitor Redis accordingly.
- **Killswitch service.** A separate deployment (`acr-killswitch`)
  holding the kill *actions*. Its state is in Redis, and the gateway's
  hot path reads that state directly from Redis — so killswitch
  service downtime does not block evaluation, but new kill/revoke
  actions need the service. One replica is functional; two remove it
  as a single point for the action path.

## Upgrade and rollback runbook

1. **Migrate first, roll second.** The gateway deployment's
   initContainer runs `scripts/run-migrations.sh` (Alembic). Each
   migration is transactional; replicas racing the init step are safe
   — the loser observes the schema already at head and exits 0.
2. **Roll the gateways.** Standard rolling update across replicas.
   Because decision recording is synchronous and sequence is assigned
   at issuance in Postgres (not in-process), mixed-version replicas
   during the roll do not fork the §18 record.
3. **Policy changes are not image changes.** Managed policy upgrades
   travel through Policy Studio releases and the bundle poll (2–5 s),
   with their own activation/rollback path — see
   `docs/managed-policy-upgrades.md`.
4. **Rollback.** Rolling back the gateway *image* to the previous
   release is the supported move and is the path the managed-upgrade
   validation exercises (below). Schema downgrades exist per
   migration, but a fleet-wide schema downgrade under live traffic is
   **not** a validated path: prefer forward fixes, and treat any
   downgrade as a maintenance-window operation with a database backup
   taken first.

## Proven vs documented-but-unproven

| Claim | Status |
|---|---|
| Two-replica gateway rollout **and rollback** with managed policy upgrade, on a real (kind) Kubernetes cluster | **Proven** — `scripts/managed_policy_validation.py` runs this in the managed-upgrade CI workflow, including hash-pinned bundle behavior |
| Full stack functionally correct (gateway, Postgres, Redis, OPA, killswitch) | **Proven** — full-stack validation workflow, every release |
| Migrations race-safe across replicas; schema at head 0022 for v1.5.0 | **Proven** — same validation paths; transactional Alembic design |
| §18 record integrity under mixed-version replicas during a roll | **Documented, partially proven** — sequence/issuance semantics are conformance-tested (v1.4.0); the mixed-version roll itself is exercised by the two-replica validation, but not under sustained production load |
| Multi-replica throughput/latency at production scale | **Unproven** — `docs/benchmarks.md` publishes a single-host floor and the harness to measure real topologies; no production-scale numbers are claimed |
| Redis HA via an external Sentinel/proxy layer | **Documented but unproven** — the single-endpoint contract is tested; any specific HA Redis arrangement is operator infrastructure, not validated by this project |
| Postgres failover mid-evaluation (managed HA or Patroni) | **Documented but unproven** — the expected behavior is fail-secure denies during the failover window and clean recovery after; no automated failover test exists in this release |
| Fresh operator reaching a running HA deployment from these docs alone | **Documented but unproven** — the manifests and this runbook are the path; an independent from-docs bring-up has not been timed or witnessed |

## Operator checklist (HA bring-up)

1. Provision Postgres (HA) + PgBouncer; create the database; note the
   pooled endpoint for `DATABASE_URL`.
2. Provision Redis with an HA endpoint; note it for `REDIS_URL`.
3. Provide secrets via your secret manager (the production overlay
   expects ExternalSecrets; the base example secret file shows the
   full key list).
4. `kubectl apply -k deploy/k8s/overlays/production` (or base for a
   first pass). The initContainer migrates the schema.
5. Verify `GET /acr/ready` reports database, Redis, and OPA ok on
   every replica — readiness failing on OPA identity means the bundle
   has not converged yet; give the poll a few seconds, then
   investigate rather than forcing traffic.
6. Run the benchmark harness against the new topology and file the
   results (`docs/benchmarks.md` § Reproducing) — an HA deployment
   without its own numbers is a hope, not a topology.
