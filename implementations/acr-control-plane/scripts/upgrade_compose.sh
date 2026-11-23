#!/usr/bin/env sh
# Controlled local Compose upgrade/rollback. Set ACR_GATEWAY_IMAGE to an immutable
# reviewed release image/digest. Does not delete DB/Redis or operator policies.
set -eu
# Git Bash/MSYS2 rewrites POSIX-looking arguments into Windows paths when a
# shell launches a native executable such as docker.exe. Every argument this
# script passes to Docker is a container path (/preflight, /operator-policies)
# or an identifier that must arrive verbatim; the rewrite corrupts the volume
# mount specs and makes the export preflight check below unreachable (its
# /preflight argument never matches), so the upgrade would proceed past a
# failed preflight instead of refusing. Opt out of the rewrite for everything
# this script launches. These variables are inert outside MSYS2 shells.
export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL='*'
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
