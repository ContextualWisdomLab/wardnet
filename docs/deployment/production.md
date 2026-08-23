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

Review `deploy/kubernetes/waf-ids-ai-soc.yaml` before applying. Replace the placeholder admin secret with a secret-manager synchronization flow.

```bash
kubectl apply -f deploy/kubernetes/waf-ids-ai-soc.yaml
```

## Production Requirements

- Terminate TLS in front of the service.
- Expose `/admin` and `/api/*` only through identity-aware access.
- Configure upstream allowlists and egress policy.
- Store `ADMIN_TOKEN` in a secret manager. The process **will not become ready** on `BIND_ADDR=0.0.0.0:8080` (or any non-loopback address) if no write-capable credential is configured. That is intentional fail-closed behavior (issue #78). Recovery: inject the Secret, restart; do not disable the gate.
- Mount persistent state or replace JSON persistence with a database.
- Run `scripts/smoke.sh` before promoting a release.
- Keep block mode route-scoped and reversible.
