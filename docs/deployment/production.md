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
- Store the write-capable admin credential in a secret manager. The process will not become ready on any non-loopback `BIND_ADDR` if no usable `ADMIN_TOKEN`, write-capable `ADMIN_TOKENS` principal, or `WAF_IDS_CREDENTIALS_PATH` credential is configured. Recovery is to provision the secret authority and restart; do not disable the gate. This fail-closed bootstrap aligns with the threat model and NIST key-management / authenticator-lifecycle guidance cited in [docs/security/threat-model.md](../security/threat-model.md).
- Mount persistent state or replace JSON persistence with a database.
- Run `scripts/smoke.sh` before promoting a release.
- Keep block mode route-scoped and reversible.
