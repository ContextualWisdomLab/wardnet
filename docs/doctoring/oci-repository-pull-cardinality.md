# OCI repository pull cardinality

## Problem

Agent Artifact Admission authorizes exact reviewed OCI artifact coordinates, including a digest-bearing command operand. Docker and Podman both expose `-a` / `--all-tags` on `pull`; their current command references define that option as pulling every tagged image in a repository. Before this repair, Wardnet ignored those option tokens because they begin with `-`, so an intent could retain an `allow` decision even though the downstream client had been asked to expand one approved artifact request into a mutable repository-wide set.

A follow-up hostile case found the first repair was syntactically incomplete. Boolean CLI options can also be supplied as assignments, including `--all-tags=true` and short-form assignments such as `-a=true`. The exact-token predicate rejected bare `-a` / `--all-tags` but did not classify assigned true forms, so the same artifact-set expansion authority could escape the admission boundary while the reviewed digest operand still matched policy.

This is an admission-authority defect, not an OCI transport implementation responsibility. Wardnet owns whether submitted structured argv stays inside the reviewed artifact set. Docker/Podman continue to own registry transport, and the downstream execution broker/quarantine path still owns retrieval, byte verification, and hostile execution isolation.

## Decision

For Docker and Podman `pull`, bare `-a` / `--all-tags` and assigned true spellings are rejected as `artifact_not_approved`. The existing artifact-variant predicate is intentionally widened to cover both platform selection and dynamic artifact-set expansion because both change artifact identity beyond the reviewed `ArtifactCoordinate` set. Explicit false assignments remain admissible because they do not widen the pull set. No new public reason code or provider-specific transport abstraction is introduced.

The decision is fail-closed until Wardnet has a versioned policy aggregate capable of enumerating every artifact that a repository-wide operation may retrieve. A mutable tag set is not equivalent to a reviewed list of exact digests.

## RED / GREEN evidence

- RED `d7f429c37a3bd26ea746254defc5d65f33ef71f2`: `oci_all_tags_contract.rs` requires Docker and Podman long/short all-tags forms to block even when the submitted operand itself is an approved digest.
- Causal GREEN source `7f06137453dc2296e4c4ac8c439777bf19ba7244`: `artifact_variant` rejects bare `-a` / `--all-tags` and the composition keeps the existing `artifact_not_approved` contract.
- Follow-up RED `883d1d37e05b0ccd9d30b2c1b25fd7d53c6fc8d8`: the hostile contract adds assigned true forms that the exact-token predicate did not reject.
- Causal GREEN `e9e07e696c013dab88df6a5a6dc1be8306b9b688`: the predicate recognizes true Boolean assignments without treating explicit false assignments as repository expansion.
- Coverage refinement `2207a6f79522dc8b6cb95e817be648bb6ef9a7f3`: exercises Docker/Podman long/short assigned true spellings and the explicit-false non-regression boundary.
- Exact-current-head workflow execution remains authoritative for terminal GREEN; predecessor workflow results do not transfer to a changed head.

## Threat effect

The repair removes a confused-deputy path where untrusted agent-supplied argv could widen a single reviewed OCI identity into every mutable tag in a repository. It does not claim that a permitted digest pull proves downloaded bytes. The execution broker must still verify the retrieved object or equivalent provenance against the admitted identity before installation or execution.

## References

Docker, Inc. (2026). *docker CLI reference*. Docker Docs. https://docs.docker.com/reference/cli/docker/

Docker, Inc. (2026). *docker image pull*. Docker Docs. https://docs.docker.com/reference/cli/docker/image/pull/

National Institute of Standards and Technology. (2022). *Secure Software Development Framework (SSDF) Version 1.1: Recommendations for mitigating the risk of software vulnerabilities (NIST SP 800-218).* https://doi.org/10.6028/NIST.SP.800-218

Podman contributors. (2026). *podman-pull*. Podman documentation. https://docs.podman.io/en/latest/markdown/podman-pull.1.html

Primary command references were re-verified on 2026-09-04. Docker documents `-a, --all-tags` as downloading all tagged images in a repository and its CLI reference documents explicit assignment syntax for Boolean options. Podman documents the equivalent all-tags option as pulling all tagged images and documents explicit true/false assignment semantics for Boolean pull options such as TLS verification. Those semantics are why assigned true all-tags forms are treated as artifact-set authority rather than harmless presentation detail.
