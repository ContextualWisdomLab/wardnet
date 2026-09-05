# OCI platform selection and artifact identity

Verified 2026-09-04. This note records the security reason Wardnet's Agent Artifact Admission boundary rejects caller-selected OCI pull platforms until platform-specific artifact identity is represented in a versioned policy contract. It does not claim OCI conformance or runtime image verification; the execution broker and quarantine runtime still verify the retrieved object and preserve request/evidence identity.

## Problem

The admission policy currently approves an OCI artifact by exact ecosystem, image name, version, registry, owner, SHA-256 digest, and submitted image reference. Docker and Podman clients can also accept caller-selected platform selectors for a pull. Docker documents `--platform` as selecting a platform when the server is multi-platform capable. Podman's current `podman pull` contract independently exposes `--platform`, `--arch`, `--os`, and `--variant`; its documentation states that these options override the host platform attributes used to select the image. The OCI Image Index specification defines an image index as a higher-level manifest that points to specific image manifests for one or more platforms.

If Wardnet authorizes only the index-level artifact coordinate but lets untrusted argv add any of those selectors, the caller has introduced an execution-relevant artifact variant that the policy did not review separately. The index digest remains content-addressed, but the selected platform-specific manifest and runtime bytes are not represented by the current `ArtifactCoordinate` contract. That is an authority gap, not merely a command-line convenience.

## Decision

Wardnet fails closed on caller-supplied `--platform` or `--platform=...` for `docker pull` and `podman pull`. For Podman, the equivalent `--arch`, `--os`, and `--variant` selector forms also fail closed. The decision uses the existing `artifact_not_approved` reason because the requested artifact variant is outside the approved coordinate; no new public reason-code contract is introduced.

The compatible control remains an exact digest pull with no caller-selected platform selector. A future released policy schema may model an approved OCI platform together with the platform-specific manifest digest or equivalent verified provenance. Until then, silently accepting platform selection would widen authority beyond the reviewed artifact identity.

This is intentionally an admission-only control. Wardnet does not copy OCI resolution or hostile-execution logic from its canonical owners, and an admission `allow` remains insufficient proof that registry retrieval returned the expected executable bytes.

## Executable evidence

- RED `831006629d5fc3530ca20038dae2388115f4e26b`: `oci_platform_variant_contract.rs` proves an otherwise approved digest pull can append `--platform=linux/arm64` and escape the artifact-variant authority represented by policy.
- Initial causal source repair: `artifact_variant.rs` identifies the unrepresented OCI `--platform` selector and the public admission composition maps it to `artifact_not_approved`/block while retaining the exact-digest no-platform control case.
- Alias RED `e24f8eaca488ae610477967aad7c697433e3b199`: the same contract proves Podman attached `--arch=`, `--os=`, and `--variant=` selectors would otherwise retain an `allow` decision despite selecting an unreviewed platform variant.
- Alias GREEN `950e1059dbdadc3e045259c7f987332f98ac9b2f`: the bounded domain predicate recognizes those Podman selector aliases without widening the public reason-code surface or affecting non-Podman command ownership.
- DDD fitness: `ddd_architecture_contract.rs` treats `artifact_variant.rs` as a domain source and keeps Axum, Tokio, filesystem, network, path, and adapter concerns out of the policy boundary.

Exact current-head CI/security/coverage/review evidence remains mandatory; queued, absent, predecessor, or wrong-PR same-SHA results do not establish GREEN.

## APA 7 references

Docker, Inc. (2026). *docker image pull*. Docker Docs. https://docs.docker.com/reference/cli/docker/image/pull/

Podman Project. (2026). *podman-pull — Pull an image from a registry*. Podman documentation. https://docs.podman.io/en/latest/markdown/podman-pull.1.html

Open Container Initiative. (2026). *OCI Image Index Specification*. https://github.com/opencontainers/image-spec/blob/main/image-index.md

Open Container Initiative. (2026). *OCI Distribution Specification*. https://github.com/opencontainers/distribution-spec/blob/main/spec.md
