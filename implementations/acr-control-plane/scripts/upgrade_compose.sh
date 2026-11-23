#!/usr/bin/env sh
# Controlled local Compose upgrade/rollback. Set ACR_GATEWAY_IMAGE to an immutable
# reviewed release image/digest. Does not delete DB/Redis or operator policies.
set -eu
# Git Bash/MSYS2 rewrites POSIX-looking arguments into Windows paths when a
# native executable is launched. The container paths this script passes to
# Docker (/preflight, /operator-policies, and the /opa entrypoint) must
# arrive verbatim: the rewrite turns /preflight into a Windows host path,
# which makes the export preflight check below unreachable (its /preflight
# argument never matches), so the upgrade would proceed past a failed
# preflight instead of refusing. Exclude ONLY those container-path
# arguments from the rewrite. A blanket exclusion (MSYS_NO_PATHCONV=1 or
# MSYS2_ARG_CONV_EXCL='*') is worse than the bug: launching a script-based
# docker (a shim with a shebang, as tests and some installs use) depends on
# the rewrite to turn the shim's own POSIX path into a Windows path its
# interpreter can open, so with conversion fully off the shim never runs
# at all. These variables are inert outside MSYS2 shells.
export MSYS2_ARG_CONV_EXCL='/preflight;/operator-policies;/opa'
: "${ACR_GATEWAY_IMAGE:?Set the exact reviewed gateway image or digest}"
: "${SERVICE_OPERATOR_API_KEY:?Set an existing auditor-authorized operator key}"
: "${OPERATOR_API_KEYS_JSON:?Configure the same operator key with auditor privileges}"
# Validate candidate core + operator policy bytes without changing the live bundle
# volume or stopping the old deployment. Failure leaves the old services running.
docker compose pull acr-gateway acr-migrate acr-policy-export opa
preflight=$(docker volume create --label acr.managed-policy-preflight=true)
trap 'docker volume rm "$preflight" >/dev/null' 0
docker compose run --rm --no-deps -v "$preflight:/preflight" --entrypoint python \
  acr-policy-export -m acr.policy_studio.core_bundle export --output /preflight \
  --extensions /operator-policies
docker compose run --rm --no-deps -v "$preflight:/preflight:ro" --entrypoint /opa \
  opa check --bundle /preflight/bundle.tar.gz
docker volume rm "$preflight" >/dev/null
trap - 0
# Compile current active Studio releases too, using a read-only database query.
# The candidate service receives DATABASE_URL and the same operator mount.
docker compose run --rm --no-deps --entrypoint python acr-gateway \
  -m acr.policy_studio.distribution preflight --extensions /operator-policies
# Stop admission during the intentionally coordinated update. Existing connections
# are drained by Compose's normal container stop timeout.
docker compose stop acr-gateway opa
docker compose run --rm --no-deps acr-policy-export
docker compose run --rm acr-migrate
docker compose up -d --no-build --force-recreate opa acr-gateway
docker compose up -d --no-build --wait --wait-timeout 180
