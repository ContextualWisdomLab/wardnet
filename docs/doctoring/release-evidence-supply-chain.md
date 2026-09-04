# Release evidence supply-chain decision

Status: Proposed while issue #84 prerequisites remain outside protected `main`.

## Problem

Wardnet has no immutable GitHub Release and protected `main` has no repository-owned release workflow. A production release therefore cannot yet bind one reviewed source revision to a packaged binary, dependency/build inputs, an SBOM, provenance, exact quality evidence, deployment identity, and rollback evidence.

Issue #84 is intentionally broader than this slice. Authentication, fail-closed egress, durable data authority, proven WAF/IDS enforcement, pinned deployment assets, production-shaped attack tests, promotion, and rehearsed rollback remain separate prerequisites. This change establishes the smallest release-evidence boundary that can be reviewed before those product prerequisites are protected truth.

## Constraints and rejected alternatives

- Do not create a GitHub Release from a pull-request head or another mutable development branch. A stable evidence dispatch must originate from protected `main` and its requested version must equal the reviewed Cargo package version.
- Do not rebuild an artifact later merely to attach evidence. The package archive, source-input hashes, SBOM, and provenance are generated in the same workflow from one checked-out source identity.
- Do not use floating GitHub Action refs. Release actions are pinned to immutable commit SHAs.
- Do not treat an attestation as a security verdict. Provenance establishes the relationship between an artifact and its build context; it does not prove that the artifact is vulnerability-free or policy-compliant.
- Do not claim SLSA v1.2 as an approved baseline. As rechecked on 2026-09-04, SLSA v1.1 is the latest Approved Specification published by the SLSA project. Likewise, NIST SP 800-218r1 / SSDF 1.2 is an Initial Public Draft, while NIST SP 800-218 / SSDF 1.1 remains the finalized publication baseline.
- SPDX 3.1 is still a release candidate as of this decision. The workflow emits SPDX JSON through the pinned Anchore/Syft action; later promotion policy must explicitly validate the emitted schema/profile rather than inferring compliance from a filename.

## Selected boundary

`.github/workflows/release.yml` is a repository-specific release-evidence workflow rather than a copied organization-wide release implementation. Pull requests exercise the build/evidence path without publishing attestations. A manual stable-evidence dispatch is accepted only from protected `main` with a canonical `MAJOR.MINOR.PATCH` value equal to `Cargo.toml`.

The workflow repeats Wardnet's repository quality contract, builds the locked Rust release binary, creates a deterministic tar archive, records SHA-256 digests for source/build inputs and outputs, emits a machine-readable release manifest, generates an SPDX JSON SBOM, and uploads the complete evidence bundle. Protected-main dispatch additionally creates GitHub/Sigstore-backed build-provenance and SBOM attestations for the exact package archive.

The workflow deliberately has `contents: read`. It does not create a tag, GitHub Release, package-registry object, container image, deployment, or promotion. That prevents a partial evidence foundation from becoming accidental production publication before issue #84's prerequisites and rollback/promotion acceptance are complete.

## RED → GREEN evidence

`tests/release_evidence_contract.rs` is the executable architecture fence. Its first commit requires a release workflow with protected-main binding, exact quality gates, locked build metadata, SHA-256 evidence, SPDX generation, attestation, immutable action pins, and non-persisted checkout credentials. That RED precedes the workflow implementation. The GREEN candidate adds only the release-evidence workflow and supporting documentation; it does not weaken any existing gate.

Exact-head hosted execution remains authoritative. Source inspection or a predecessor run is not GREEN. The candidate remains dependent on the Rust toolchain prerequisite represented by PR #77 and must be non-force restacked or retargeted when that prerequisite reaches protected `main`.

## Risks and follow-up

The binary-only SBOM is not yet the final container-filesystem SBOM required by #84. The workflow also does not prove bit-for-bit reproducibility across independent builders, image-digest promotion, Sigstore verification at admission, Kubernetes deployment-by-digest, attack-path execution, database migration compatibility, canary criteria, or measured rollback. Those omissions remain fail-closed release gaps rather than implied future behavior.

Before #84 can close, extend the same source identity into the final OCI image and release manifest, verify attestations before promotion, exercise production-shaped deployment/attack/rollback paths, preserve all evidence independently of ephemeral workflow retention, and publish an immutable release only after the exact protected candidate satisfies the then-live ruleset and security contract.

## Traceability

GitHub. (2026). *Using artifact attestations to establish provenance for builds*. GitHub Docs. https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations

National Institute of Standards and Technology. (2022). *Secure software development framework (SSDF) version 1.1: Recommendations for mitigating the risk of software vulnerabilities* (NIST SP 800-218). https://doi.org/10.6028/NIST.SP.800-218

National Institute of Standards and Technology. (2025). *Secure software development framework (SSDF) version 1.2: Recommendations for mitigating the risk of software vulnerabilities* (Initial Public Draft, NIST SP 800-218r1). https://csrc.nist.gov/pubs/sp/800/218/r1/ipd

SPDX Workgroup. (2024). *SPDX specification 3.0.1*. Linux Foundation. https://spdx.github.io/spdx-spec/v3.0.1/

Supply-chain Levels for Software Artifacts. (2025). *SLSA version 1.1*. https://slsa.dev/spec/v1.1/
