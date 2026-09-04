# Production Deployment Guide

## Container

Build:

```bash
docker build -t contextualwisdomlab/waf-ids-ai-soc:local .
```

Run:

```bash
docker run --rm \
  -p 8080:8080 \
  -e BIND_ADDR=0.0.0.0:8080 \
  -e ADMIN_TOKEN=replace-me \
  -e DNSBL_ORIGIN=dnsbl.example \
  -v waf_ids_state:/var/lib/waf-ids-ai-soc \
  contextualwisdomlab/waf-ids-ai-soc:local
```

## Compose

```bash
cd deploy
ADMIN_TOKEN=replace-me docker compose up --build
```

## Kubernetes

The distributable manifest does not create an administrator Secret. A fresh cluster must create the namespace before any namespaced Secret or ExternalSecret can exist. Bootstrap the namespace idempotently first:

```bash
kubectl create namespace waf-ids-ai-soc --dry-run=client -o yaml | kubectl apply -f -
```

Then use the organization's secret-management control plane to provision an Opaque Secret named `waf-ids-ai-soc-admin` in namespace `waf-ids-ai-soc` with key `ADMIN_TOKEN`. Keep access to that Secret limited to the workload and operational identities that require it. Existing installations may run the same namespace-bootstrap command safely; it converges on the existing Namespace rather than replacing it.

The Deployment binds `ADMIN_TOKEN` only through that `secretKeyRef` with `optional: false`. If the Secret or key is absent, the workload does not start; there is no repository-provided fallback credential.

After the external secret controller reports successful synchronization, apply the complete manifest. Its Namespace object remains in the declarative asset so later applies retain the same ownership boundary:

```bash
kubectl apply -f deploy/kubernetes/waf-ids-ai-soc.yaml
```

When rotating `ADMIN_TOKEN`, wait for the updated Secret to synchronize, then restart the Deployment because environment-variable-backed Secret values are fixed when a container starts. Verify the rollout and readiness before revoking the previous token:

```bash
kubectl -n waf-ids-ai-soc rollout restart deployment/waf-ids-ai-soc
kubectl -n waf-ids-ai-soc rollout status deployment/waf-ids-ai-soc
```

Failure, recovery, verification, and evidence requirements are documented in [`../doctoring/kubernetes-admin-secret-boundary.md`](../doctoring/kubernetes-admin-secret-boundary.md).

## Production Requirements

- Terminate TLS in front of the service.
- Expose `/admin` and `/api/*` only through identity-aware access.
- Configure upstream allowlists and egress policy.
- Store the write-capable administrator credential in a secret manager. The process will not become ready on any non-loopback `BIND_ADDR` if no usable `ADMIN_TOKEN`, write-capable `ADMIN_TOKENS` principal, or `WAF_IDS_CREDENTIALS_PATH` credential is configured. Recovery is to provision the secret authority and restart; do not disable the gate. This fail-closed bootstrap aligns with the threat model and the NIST guidance cited in [docs/security/threat-model.md](../security/threat-model.md).
- Mount persistent state or replace JSON persistence with a database.
- Run `scripts/smoke.sh` before promoting a release.
- Keep block mode route-scoped and reversible.
