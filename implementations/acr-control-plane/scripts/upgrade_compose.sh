#!/usr/bin/env sh
# Controlled local Compose upgrade/rollback. Set ACR_GATEWAY_IMAGE to an immutable
# reviewed release image/digest. Does not delete DB/Redis or operator policies.
set -eu
: "${ACR_GATEWAY_IMAGE:?Set the exact reviewed gateway image or digest}"
: "${SERVICE_OPERATOR_API_KEY:?Set an existing auditor-authorized operator key}"
: "${OPERATOR_API_KEYS_JSON:?Configure the same operator key with auditor privileges}"
# Stop admission during the intentionally coordinated update. Existing connections
# are drained by Compose's normal container stop timeout.
docker compose stop acr-gateway opa
docker compose pull acr-gateway acr-migrate acr-policy-export
docker compose run --rm --no-deps acr-policy-export
docker compose run --rm acr-migrate
docker compose up -d --no-build --force-recreate opa acr-gateway
docker compose up -d --no-build --wait --wait-timeout 180
