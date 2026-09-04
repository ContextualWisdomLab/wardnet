# OCI repository pull cardinality

## Problem

Agent Artifact Admission authorizes exact reviewed OCI artifact coordinates, including a digest-bearing command operand. Docker and Podman both expose `-a` / `--all-tags` on `pull`; their current command references define that option as pulling every tagged image in a repository. Before this repair, Wardnet ignored those option tokens because they begin with `-`, so an intent could retain an `allow` decision even though the downstream client had been asked to expand one approved artifact request into a mutable repository-wide set.

This is an admission-authority defect, not an OCI transport implementation responsibility. Wardnet owns whether submitted structured argv stays inside the reviewed artifact set. Docker/Podman continue to own registry transport, and the downstream execution broker/quarantine path still owns retrieval, byte verification, and hostile execution isolation.

## Decision

For Docker and Podman `pull`, `-a` and `--all-tags` are rejected as `artifact_not_approved`. The existing artifact-variant predicate is intentionally widened to cover both platform selection and dynamic artifact-set expansion because both change artifact identity beyond the reviewed `ArtifactCoordinate` set. No new public reason code or provider-specific transport abstraction is introduced.

The decision is fail-closed until Wardnet has a versioned policy aggregate capable of enumerating every artifact that a repository-wide operation may retrieve. A mutable tag set is not equivalent to a reviewed list of exact digests.

## RED / GREEN evidence

- RED `d7f429c37a3bd26ea746254defc5d65f33ef71f2`: `oci_all_tags_contract.rs` requires Docker and Podman long/short all-tags forms to block even when the submitted operand itself is an approved digest.
- Causal GREEN source `7f06137453dc2296e4c4ac8c439777bf19ba7244`: `artifact_variant` rejects `-a` / `--all-tags` and the composition keeps the existing `artifact_not_approved` contract.
- Exact-current-head workflow execution remains authoritative for terminal GREEN; predecessor workflow results do not transfer to a changed head.

## Threat effect

The repair removes a confused-deputy path where untrusted agent-supplied argv could widen a single reviewed OCI identity into every mutable tag in a repository. It does not claim that a permitted digest pull proves downloaded bytes. The execution broker must still verify the retrieved object or equivalent provenance against the admitted identity before installation or execution.

## References

Docker, Inc. (2026). *docker image pull*. Docker Docs. https://docs.docker.com/reference/cli/docker/image/pull/

National Institute of Standards and Technology. (2022). *Secure Software Development Framework (SSDF) Version 1.1: Recommendations for mitigating the risk of software vulnerabilities (NIST SP 800-218).* https://doi.org/10.6028/NIST.SP.800-218

Podman contributors. (2026). *podman-pull*. Podman documentation. https://docs.podman.io/en/latest/markdown/podman-pull.1.html

Primary command references were re-verified on 2026-09-04. Docker documents `-a, --all-tags` as downloading all tagged images in a repository. Podman documents the equivalent option as pulling all tagged images in the repository. Those semantics are the reason this option is treated as artifact-set authority rather than harmless client presentation detail.
