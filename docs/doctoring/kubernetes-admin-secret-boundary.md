# Kubernetes administrator Secret boundary

## Decision

Wardnet's distributable Kubernetes manifest must not create or embed an administrator credential. The manifest consumes one externally provisioned Secret only:

- namespace: `waf-ids-ai-soc`
- Secret: `waf-ids-ai-soc-admin`
- key: `ADMIN_TOKEN`
- consumer: Deployment `waf-ids-ai-soc`, container `gateway`
- reference: `env[name=ADMIN_TOKEN].valueFrom.secretKeyRef`
- availability contract: `optional: false`

The secret-management control plane owns generation, storage, synchronization, rotation, recovery, and revocation. Wardnet owns the fail-closed consumption contract and must never add a repository-visible fallback value.

This boundary is deliberately narrow. It removes the distributable placeholder credential; it does **not** close the separate runtime-authentication problem tracked in issue #78, where a non-loopback process must also refuse readiness when no write-capable authentication authority is configured.

## Why this is a production boundary

A reusable value committed in a deployment asset is part of the product's distributed attack surface even when its text says "replace me". Operators can apply the asset without editing it, scanners and downstream forks retain it, and a common value can become an implicit shared administrator credential. MITRE classifies hard-coded credentials as CWE-798. Kubernetes likewise warns against sharing Secret manifests and recommends limiting Secret access to only the containers that require it.

The replacement therefore follows fail-safe defaults and least privilege: a missing credential prevents the workload from starting rather than silently selecting a repository default, and the Secret is referenced only by the gateway container that consumes it.

## Provisioning and deployment

Before applying `deploy/kubernetes/waf-ids-ai-soc.yaml`, the deployment authority must confirm that its external secret manager/controller has materialized `waf-ids-ai-soc-admin` in namespace `waf-ids-ai-soc` with a non-empty `ADMIN_TOKEN` key. The repository does not prescribe a vendor-specific controller; the integration boundary is the Kubernetes Secret coordinates above.

Apply the Wardnet manifest only after synchronization succeeds. Kubernetes resolves the `secretKeyRef` when creating the container. Because the reference is explicitly non-optional, absence of the Secret or key is an operator-visible startup failure instead of an authentication downgrade.

## Rotation

`ADMIN_TOKEN` is injected as an environment variable. Kubernetes documents that a container does not observe an updated Secret-backed environment variable until the container is restarted. Rotation therefore uses this order:

1. Generate a new credential in the authoritative secret manager and synchronize it to the Kubernetes Secret.
2. Confirm the synchronized Secret exists and contains the expected key without printing its value.
3. Run a controlled `rollout restart` of Deployment `waf-ids-ai-soc`.
4. Wait for `rollout status` and application readiness to succeed.
5. Exercise an authenticated management request with the new credential through the approved operational path.
6. Revoke the previous credential only after the new workload is healthy.

If rollout or authentication verification fails, keep or restore the previous credential in the external authority, resynchronize, restart the Deployment again, and verify readiness before resuming normal operations. Do not add a literal emergency token to this repository or manifest as a recovery shortcut.

## Verification contract

`tests/deployment_manifest.rs` is the permanent regression boundary. It fails if the shipped manifest contains a `kind: Secret` document or the historical placeholder value. It also structurally selects Deployment `waf-ids-ai-soc`, scopes the lookup to the `gateway` runtime container, finds the `ADMIN_TOKEN` environment entry, and validates the expected namespace, Secret name, key, and non-optional reference. Decoy Deployments, `initContainers`, comments, and `optional: true` cannot satisfy the contract.

For release evidence, run the repository's normal formatting, workspace test, Clippy, fuzz, SAST, and Security Scan gates on the exact PR head. A predecessor-head success, skipped required job, or security scan from another merge tree is not evidence for the current artifact.

## Audit and incident handling

Evidence suitable for deployment/change review should record the external-secret synchronization result, Deployment revision, rollout completion, readiness result, and credential-rotation event identifier. It must not contain the credential value, a recoverable encoding of it, request headers carrying it, or Secret-object dumps.

If a repository-visible credential is discovered later, treat it as compromised regardless of whether it was intended as an example: remove the value from distributable assets, rotate the external credential, check Git and artifact history for exposure scope, invalidate affected credentials, and retain the remediation evidence required by the organization's incident process.

## Research and standards traceability

Kubernetes' current Secret documentation defines `env[].valueFrom.secretKeyRef` as the environment-variable consumption mechanism. Its security good-practices guidance recommends restricting Secret access to only the containers that require it and warns against checking Secret manifests into source repositories. Kubernetes also documents that Secret-backed environment variables require a container restart to observe a changed value. These contracts directly support the manifest shape and rotation procedure used here.

NIST SP 800-57 Part 1 Rev. 5 remains the final Recommendation for general key-management practice as of this decision; Revision 6 is still an Initial Public Draft. Although `ADMIN_TOKEN` is an authentication secret rather than necessarily cryptographic keying material, the lifecycle principles around protected storage, access control, compromise response, replacement, and recovery are applicable to secret-management operations.

Saltzer and Schroeder's fail-safe-defaults and least-privilege principles support making absence of the external Secret an explicit deployment failure and limiting its consumption boundary. Krause et al.'s mixed-methods study of source-repository secret leakage found that developers continue to encounter secret exposure and remediation difficulties; the practical implication here is to remove the credential value from version control entirely rather than relying on an instruction to replace it later.

No research PDF is committed in this change. The IEEE article is not redistributed under a repository-compatible open license, and the USENIX paper is publicly downloadable but its conference open-access statement does not by itself establish a redistribution license for repackaging in this repository. Both are cited and linked instead.

## References

Barker, E. (2020). *Recommendation for key management: Part 1—General* (NIST Special Publication 800-57 Part 1 Rev. 5). National Institute of Standards and Technology. https://doi.org/10.6028/NIST.SP.800-57pt1r5

Krause, A., Klemmer, J. H., Huaman, N., Wermke, D., Acar, Y., & Fahl, S. (2023). Pushed by accident: A mixed-methods study on strategies of handling secret information in source code repositories. In *32nd USENIX Security Symposium (USENIX Security 23)* (pp. 2527–2544). USENIX Association. https://www.usenix.org/conference/usenixsecurity23/presentation/krause

Kubernetes Authors. (2025). *Good practices for Kubernetes Secrets*. Kubernetes. https://kubernetes.io/docs/concepts/security/secrets-good-practices/

Kubernetes Authors. (2026). *Secrets*. Kubernetes. https://kubernetes.io/docs/concepts/configuration/secret/

Kubernetes Authors. (2026). *Distribute credentials securely using Secrets*. Kubernetes. https://kubernetes.io/docs/tasks/inject-data-application/distribute-credentials-secure/

MITRE. (2026). *CWE-798: Use of hard-coded credentials*. Common Weakness Enumeration. https://cwe.mitre.org/data/definitions/798.html

Saltzer, J. H., & Schroeder, M. D. (1975). The protection of information in computer systems. *Proceedings of the IEEE, 63*(9), 1278–1308. https://doi.org/10.1109/PROC.1975.9939
