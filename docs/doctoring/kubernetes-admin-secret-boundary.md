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
credential returns, or when the `Deployment` document does not structurally bind
`env[name=ADMIN_TOKEN].valueFrom.secretKeyRef` to Secret
`waf-ids-ai-soc-admin`, key `ADMIN_TOKEN`, in namespace `waf-ids-ai-soc`. An
adversarial fixture confirms that unrelated or commented occurrences of those
strings cannot satisfy the contract.

Repository CI must run the full Rust workspace tests, formatting, and Clippy on
the exact pull-request head. The organization Security Scan remains authoritative
for dependency, filesystem, and supply-chain findings.

## Rotation and rollback

After the external secret controller reports successful synchronization, restart
the Deployment in a controlled rollout and verify readiness before revoking the
old token. Environment-variable-backed Secret values are fixed when the process
starts and are not refreshed in an already running container.

Reverting this change restores the unsafe shared credential and is therefore not
an acceptable operational rollback. To recover from a failed deployment, create
or restore the externally managed `waf-ids-ai-soc-admin` Secret with a newly
issued `ADMIN_TOKEN`, verify least-privilege access, and restart the affected
Pods. Preserve the prior token only for the bounded overlap required to verify
the rollout, then revoke it and retain the rotation audit record.

## Research basis

Krause et al. (2023) found through a mixed-methods study that accidental secret
leakage remains common and that remediation mechanisms need low adoption cost.
That evidence supports removing even example credentials from source-controlled
manifests and keeping the operational contract to one externally synchronized
Secret reference.

Saltzer and Schroeder's (1975) fail-safe-default and least-privilege principles
support refusing startup when the credential is absent and restricting access to
the smallest set of workload and operator identities. NIST key-management
guidance additionally supports explicit credential lifecycle, recovery, and
revocation procedures. The Kubernetes documentation is authoritative for the
platform-specific fact that Secret-backed environment variables require a
container restart to observe an updated value.

Peer-reviewed papers are linked to their DOI or publisher-maintained open-access
copy rather than vendored as binaries. This preserves provenance and avoids
redistributing papers without an explicit repository-compatible license.

## References

Barker, E. (2020). *Recommendation for key management: Part 1—General*
(NIST Special Publication 800-57 Part 1 Revision 5). National Institute of
Standards and Technology. https://doi.org/10.6028/NIST.SP.800-57pt1r5

Krause, A., Klemmer, J. H., Huaman, N., Wermke, D., Acar, Y., & Fahl, S.
(2023). Pushed by accident: A mixed-methods study on strategies of handling
secret information in source code repositories. In *32nd USENIX Security
Symposium (USENIX Security 23)* (pp. 2527–2544). USENIX Association.
https://www.usenix.org/conference/usenixsecurity23/presentation/krause

Kubernetes Authors. (n.d.). *Distribute credentials securely using Secrets*.
Kubernetes. Retrieved August 6, 2026, from
https://kubernetes.io/docs/tasks/inject-data-application/distribute-credentials-secure

Kubernetes Authors. (n.d.). *Good practices for Kubernetes Secrets*.
Kubernetes. Retrieved August 6, 2026, from
https://kubernetes.io/docs/concepts/security/secrets-good-practices/

Kubernetes Authors. (n.d.). *Secrets*. Kubernetes. Retrieved August 6, 2026,
from https://kubernetes.io/docs/concepts/configuration/secret/

MITRE. (2026). *CWE-798: Use of hard-coded credentials (Version 4.20)*.
https://cwe.mitre.org/data/definitions/798.html

Saltzer, J. H., & Schroeder, M. D. (1975). The protection of information in
computer systems. *Proceedings of the IEEE, 63*(9), 1278–1308.
https://doi.org/10.1109/PROC.1975.9939
