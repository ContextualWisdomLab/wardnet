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

The distributable manifest deliberately does not create an administrator
Secret. Before applying it, configure an external secret manager or equivalent
synchronization flow to create the Opaque Secret `waf-ids-ai-soc-admin` in the
`waf-ids-ai-soc` namespace with the key `ADMIN_TOKEN`. Restrict access to that
Secret through namespace-scoped, least-privilege RBAC and enable encryption at
rest for Kubernetes Secrets.

The Deployment consumes only that named key through `secretKeyRef`. If the
Secret or key is absent, Kubernetes prevents the container from starting rather
than falling back to a shared credential.

```bash
kubectl apply -f deploy/kubernetes/waf-ids-ai-soc.yaml
```

## Production Requirements

- Terminate TLS in front of the service.
- Expose `/admin` and `/api/*` only through identity-aware access.
- Configure upstream allowlists and egress policy.
- Store `ADMIN_TOKEN` in a secret manager.
- Mount persistent state or replace JSON persistence with a database.
- Run `scripts/smoke.sh` before promoting a release.
- Keep block mode route-scoped and reversible.
