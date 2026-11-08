# Blessed Production Deployment

This overlay is the supported production deployment path for the ACR control plane.

It assumes:

- Kubernetes as the runtime platform
- External Secrets Operator for application secret material
- managed PostgreSQL and managed Redis
- OIDC-first operator authentication
- S3 or an S3-compatible object store for policy bundle publishing
- ingress-nginx plus cert-manager for north-south traffic
- internal executors reachable only on private networks

It is opinionated on purpose. This path exists so platform and security teams have one deployment model to review, harden, and automate.

## What This Overlay Changes

Relative to `deploy/k8s/base`, this overlay:

- removes the example secret from the runtime path and expects a real `ExternalSecret`
- retains published artifacts in object storage and uses authenticated, core-qualified bundle polling from each local OPA sidecar
- assumes OIDC is the normal operator login path
- replaces the base gateway and kill-switch network policy with a production egress allowlist
- adds namespace pod-security labels
- adds rollout settings like `minReadySeconds`, `progressDeadlineSeconds`, and topology spreading
- points workloads at release images rather than local `acr-gateway:1.0.0` tags

## Before You Apply It

1. Create a `ClusterSecretStore` or `SecretStore` for your secret manager.
2. Edit [external-secret.yaml](external-secret.yaml):
   - `secretStoreRef.name`
   - remote secret keys and property names
3. Edit [networkpolicy-production.yaml](networkpolicy-production.yaml):
   - replace all `203.0.113.x/32` placeholder CIDRs
   - add or remove executor namespaces as needed
4. Edit [gateway-configmap-patch.yaml](gateway-configmap-patch.yaml):
   - hostnames
   - object-storage details
   - OIDC details
   - OTLP endpoint if used
5. Edit [ingress-patch.yaml](ingress-patch.yaml):
   - public host
   - TLS secret
6. Make sure your cluster can pull the release images:
   - mirror them into your internal registry, or
   - create a registry pull secret if your GHCR packages are private
7. Replace the example release tags in [kustomization.yaml](kustomization.yaml) with your promoted image digests before production promotion.

## Build and Review

```bash
kubectl kustomize deploy/k8s/overlays/production
```

## Apply

```bash
kubectl apply -k deploy/k8s/overlays/production
```

## Post-Deploy Validation

- `kubectl -n acr-system get externalsecret,secret`
- `kubectl -n acr-system get pods`
- `kubectl -n acr-system rollout status deploy/acr-gateway`
- `kubectl -n acr-system rollout status deploy/acr-killswitch`
- Verify `/acr/ready` on each gateway Pod; OPA is a per-Pod sidecar, not a separate Deployment.
- `curl https://acr.example.com/acr/health`
- `curl https://acr.example.com/acr/ready`
- validate OIDC login, policy activation, approval flow, evidence export, and executor reachability

## Why This Is The Blessed Path

This is the path that closes the earlier gaps:

- no runtime application of example secrets
- one explicit secrets-management model
- one explicit network-enforcement story
- object storage instead of local bundle state
- one ingress and rollout model for production

If you diverge from this overlay, treat it as a custom platform variant and review it accordingly.

## Release-paired core policies

Read [the managed upgrade guide](../../../../docs/managed-policy-upgrades.md) before migrating from 1.2.1. Preserve the operator ConfigMap and active database policies. Select one immutable gateway image for the gateway and both init containers. The checked-in `1.3.0` tag is an example, not permission to deploy or a claim the image is already published.

Before rollout or rollback, pause approval processing and new evaluations, resolve
or deny pending approvals, and drain in-flight approved executions. The managed
identity gate applies to new OPA evaluations, not the preexisting approved-action
execution path. See the managed upgrade guide for this unvalidated cross-release
approval/replay boundary.
