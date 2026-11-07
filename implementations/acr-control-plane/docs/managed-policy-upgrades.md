# Managed core policy upgrades (1.3.0)

A gateway release owns the exact `common.rego` and `content_safety.rego` bytes it
requires. The installed Python wheel and gateway image carry these resources.
OPA receives one aggregate bundle: packaged core + operator files + active Policy
Studio releases from the database. No cron updates, mutable `latest` policy
channel, manual core-file copying, or raw-JSON OPA discovery are used.

The exporter generates a direct OPA bundle configuration pinned to the gateway's
core ID. New gateway policy evaluations verify that identity **in the same OPA
response**; readiness also checks it. Missing, stale, or mixed core rejects new
policy evaluations. These checks do not cover every downstream execution. This
checks accidental version skew, not remote attestation of a malicious OPA server.
Active database-policy publication retains its existing asynchronous polling
semantics: core/local-extension readiness does not prove a just-activated Studio
revision has propagated. Verify the desired policy decision after activation.

## Approval processing boundary and cutover prerequisite

The preexisting approved-action path, `execute_approval` in
`src/acr/pillar6_authority/approval.py`, calls the executor without a fresh OPA
policy evaluation. New core/local-extension identity checks therefore do not
revalidate pending approvals, previously approved actions, or their execution
under a later release. Gateway readiness is not a replacement for controlling
approval processing, especially for direct requests outside readiness-based routing.

Before any upgrade, rollback, or policy cutover, pause approval processing and
stop new evaluations that could create pending approvals. Inventory outstanding
approvals and resolve them under the existing reviewed policy, or deliberately
deny them and require a new evaluation after cutover. Drain any in-flight approved
executions before replacing the release. Keep approval processing paused until
new evaluations and the intended policy behavior have been verified. The upgrade
script does not automate this approval inventory or resolution.

This change does not alter the approved-action/replay lifecycle. Its behavior
across release upgrades or rollback is a preexisting, unvalidated limitation of
this upgrade workflow, even though ordinary approval/replay tests exist. Do not
claim that a matching core identity reauthorizes stored approvals.

## One-time migration from 1.2.1

1. Complete the approval-processing prerequisite above. Back up the database,
   deployment configuration and entire old policy directory.
   Retain the old immutable gateway image and release configuration for rollback.
2. Run `python scripts/migrate_operator_policies.py policies/acr operator-policies`.
   This copies customer-support and custom `.rego` files without modifying the
   source. Exact old shipped core files and test modules are excluded. Changed
   core or conflicting destination files cause an actionable refusal before any
   copies. Extract reviewed local core modifications into separate extension rules
   before retrying. Never delete those modifications just to make migration pass.
3. Preserve `operator-policies/` as operator-owned configuration. Do not replace it
   with a later checkout's sample directory. Existing files use `package acr` or
   an `acr` subpackage; core identity names are reserved. Only `.rego` files and
   `.gitkeep` are accepted. Data JSON/YAML, archives,
   manifests and any other input cause refusal before copying anything, since
   silently omitting data can weaken a deny rule. Review and convert unsupported
   inputs or wait for explicit support; keep the original deployment until then.
   Arbitrary outside-`acr` packages also require review.
4. Set both `OPERATOR_API_KEYS_JSON` and `SERVICE_OPERATOR_API_KEY`. The latter
   must identify an existing key in the former with `auditor` (or an equivalent
   allowed bundle-read role). Empty values fail immediately in Compose. Use the
   existing secret mechanism, not a new default credential. Keep bundle auth on.
5. On Kubernetes, preserve your migrated files in `acr-operator-policies` instead
   of applying the sample ConfigMap over them. The base now pairs OPA with each
   gateway Pod; remove the obsolete standalone `acr-opa` Deployment/Service/HPA/PDB
   only after the new gateway Pods are ready and old gateway Pods are drained.
   `kubectl apply` alone does not prune those old resources.

## Intentional Compose release upgrade or rollback

Set `ACR_GATEWAY_IMAGE` to the reviewed release, preferably an immutable digest,
then run `scripts/upgrade_compose.sh`. Use the same command with the retained
prior managed release image to roll back. Complete the approval-processing
prerequisite first. The script deliberately stops the gateway,
exports the new pinned OPA config, runs schema migrations, and restarts both
services. It never deletes operator files or database/Redis volumes. Do not run
`down -v` on a real deployment. A failed update leaves the gateway stopped or
unready, and new evaluations reject stale core. Stored approval execution is
outside this identity check. Investigate logs and retry the
same image or restore the previous reviewed image.

Rollback of application/policy artifacts does not reverse database migrations.
Check schema backward compatibility before rollback; restore the tested backup if
necessary. A return to pre-managed 1.2.1 additionally requires its saved Compose
configuration and legacy policy tree, not just changing the new image variable.

## Kubernetes release upgrade or rollback

Use the supported production overlay, replacing its `1.3.0` example image tag
with a reviewed immutable digest. The same image replacement must cover gateway,
policy-export init container, and migration init container. Kustomize's image
transform does all three. The OPA sidecar runs the tested `0.70.0` version.

Each Pod exports a core-pinned configuration before startup. OPA polls the gateway
on localhost; the gateway serves authenticated bundles before being ready for
user traffic. There is no gateway Service-readiness dependency and no shared OPA
pool mixing releases. Operator ConfigMaps and the active Studio database records
remain independent of the image. Rollbacks reuse the previous Pod template/image
and preserve both. Version-qualified bundle URLs return 404 on the wrong core.

Wait for `kubectl rollout status deployment/acr-gateway -n acr-system` and verify
`/acr/ready` on **every** new Pod. Mixed gateway releases during an ordinary rolling
update each enforce their matching core for new evaluations. If a policy change
must take effect across all traffic simultaneously, pause new evaluations and
approval processing, drain in-flight executions, and use a planned stop or
blue/green cutover. A rolling update is not an atomic fleet-wide policy cutover.

Update local operator files/ConfigMaps only intentionally and roll the gateway
Pods after review. Avoid changing them during a core rollout. These files are
read during bundle assembly; they are never silently overwritten by the image.

## Python install and services-only integration

Use `python -m acr.policy_studio.core_bundle export --output NEW_DIRECTORY
--extensions operator-policies --gateway-url http://127.0.0.1:8000` after installing
the exact release wheel. Export refuses different existing output by default;
`--replace` changes only its three generated artifacts, not operator files.

Run OPA with `run --server --config-file=NEW_DIRECTORY/opa-config.yaml`, set
`ACR_BUNDLE_API_KEY` to the existing operator service key, and point the gateway's
`POLICY_EXTENSION_DIR` at the same directory of operator policies. Wait for gateway
readiness before routing traffic. The exported `bundle.tar.gz` is a static seed
for diagnostic or services-only tests, not a substitute for active Studio policy
polling. Do not load static and polling bundles over the same `acr` root.

The `docker-compose.integration.yml` override deliberately uses only that static
seed for Python integration tests running without a gateway. It is not a supported
production configuration and does not exercise dynamic policy releases.

## Evidence and limitations

`ACR managed policy upgrade validation` builds two synthetic release images with
different core digests and exercises actual Docker and disposable kind Kubernetes
upgrade/rollback. It checks custom policy and active Studio release preservation,
readiness, allow/deny outcomes, and stale-core refusal. The Kubernetes test rolls
two gateway replicas and checks readiness per Pod. It does not deploy to production
or call real enterprise executors. The separate full-stack workflow verifies
execution against a synthetic protected executor. The migration checks run offline.

A passing render or static unit test is not proof of a live Kubernetes rollout.
Review terminal CI results and the attached evidence for the exact commit before
publishing a release. Production network policy/CNI behavior, external S3/OIDC,
real secrets and database rollback must be validated in your own staging system.
