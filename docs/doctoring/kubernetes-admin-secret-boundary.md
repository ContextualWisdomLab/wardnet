# Kubernetes Administrator Secret Boundary

## Incident

The distributable Kubernetes manifest previously created an Opaque Secret whose
`ADMIN_TOKEN` value was the repository-visible string
`replace-with-secret-manager-sync`. Applying the manifest without first editing
that value deployed a shared, publicly knowable credential for management-write
routes. This is a hard-coded credential boundary failure (CWE-798), not a safe
example default.

## Decision

Wardnet no longer distributes an administrator Secret object. The Deployment
continues to request exactly one key, `ADMIN_TOKEN`, from the namespaced Secret
`waf-ids-ai-soc-admin` through `secretKeyRef`.

Operators must provision that Secret before applying the manifest by using an
external secret store, a secret synchronization controller, or an equivalent
organization-controlled process. Kubernetes prevents the container from
starting when the required Secret or key is absent, so deployment fails closed
instead of silently using a reusable credential.

This boundary deliberately preserves the existing process-environment contract.
Changing to projected files, a sidecar, or live credential reload would require
a separate design that defines rotation, process restart, observability, and
failure semantics.

## Security Controls

- The repository contains no administrator credential value in the Kubernetes
  manifest.
- The Secret name and key are explicit and bounded.
- Production operators should enable encryption at rest for Secrets.
- RBAC should grant only the service account and operational identities that
  require the Secret access.
- Secret-store synchronization must complete before the Deployment is applied.
- Rotation of an environment-variable-backed Secret requires a controlled Pod
  restart because running containers do not automatically receive updated
  environment-variable values.

## Verification

`tests/deployment_manifest.rs` is a permanent regression contract. It fails when
any Kubernetes document declares `kind: Secret`, when the historical placeholder
credential returns, or when the Deployment loses its expected `secretKeyRef`
name or key.

Repository CI must run the full Rust workspace tests, formatting, and Clippy on
the exact pull-request head. The organization Security Scan remains authoritative
for dependency, filesystem, and supply-chain findings.

## Rollback

Reverting this change restores the unsafe shared credential and is therefore not
an acceptable operational rollback. To recover from a failed deployment, create
or restore the externally managed `waf-ids-ai-soc-admin` Secret with a newly
issued `ADMIN_TOKEN`, verify least-privilege access, and restart the affected Pod.

## References

Kubernetes Authors. (n.d.). *Distribute credentials securely using Secrets*.
Kubernetes. Retrieved August 6, 2026, from
https://kubernetes.io/docs/tasks/inject-data-application/distribute-credentials-secure

Kubernetes Authors. (n.d.). *Secrets*. Kubernetes. Retrieved August 6, 2026,
from https://kubernetes.io/docs/concepts/configuration/secret/

MITRE. (2026). *CWE-798: Use of hard-coded credentials (Version 4.20)*.
https://cwe.mitre.org/data/definitions/798.html
