# Doctoring — signed release, SBOM, and provenance

This note grounds issue #84 remainder (keyless Sigstore signatures and
SBOM/SLSA attestations on the same `vX.Y.Z` tag as checksums/GHCR).
IEEE/ACM PDFs are not redistributed. NIST SP 800-218 is a U.S. government
work and is committed at `docs/papers/nist-sp-800-218-ssdf.pdf`.

## Adopted standards and literature

Sigstore. (n.d.). *Cosign documentation*. https://docs.sigstore.dev/cosign/

- **Design impact:** The release workflow uses GitHub OIDC (`id-token: write`)
  for keyless signing. No long-lived Cosign key is stored. Blobs (binary,
  `SHA256SUMS`, SBOMs, image digest file) get `cosign sign-blob` bundles.
  The GHCR image is signed by digest (`image@sha256:…`), never by a moving
  tag.

SLSA Project. (2025). *SLSA specification version 1.2*.
https://slsa.dev/spec/v1.2/

- **Design impact:** `actions/attest-build-provenance` binds the binary and
  the image digest to in-toto SLSA provenance. `actions/attest-sbom` binds
  SPDX SBOMs to the same subjects. GitHub Release is created only after
  signatures and attestations succeed.

National Institute of Standards and Technology. (2022). *Secure Software
Development Framework (SSDF) version 1.1* (NIST SP 800-218).
https://doi.org/10.6028/NIST.SP.800-218
`docs/papers/nist-sp-800-218-ssdf.pdf`

- **Design impact:** PS.3 / PW.4 — produce integrity evidence (checksums,
  SBOM, signatures, provenance) for the shipped artifact. A tag alias is
  not promotion authority; operators verify the digest and signatures
  (`docs/runbooks/release.md`).

Anchore. (n.d.). *Syft*. https://github.com/anchore/syft

- **Design impact:** `scripts/release-sbom.sh` fails closed without Syft and
  rejects non-SPDX JSON. Binary and container filesystem SBOMs are both
  attached to the GitHub Release.

## Operator next action

Tag `vX.Y.Z` from the reviewed merge commit on `main`. After the Release
workflow finishes, verify with the commands in `docs/runbooks/release.md`.
Point Kubernetes at the digest in `IMAGE-DIGEST.txt`, not at `latest`.
