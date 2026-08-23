# Release, promotion, and rollback

Issue #84. IEEE/ACM PDFs are not redistributed. Buyer evidence path:
`GET /api/commercial/evidence-manifest` lists this runbook. NIST SP 800-218
is committed at `docs/papers/nist-sp-800-218-ssdf.pdf`.

## Immutable artifacts

A git tag `vX.Y.Z` starts `.github/workflows/release.yml`, which:

1. Builds `waf-ids-ai-soc` with `cargo build --locked --release`
2. Writes basename `SHA256SUMS` via `scripts/release-checksums.sh`
3. Writes SPDX SBOMs via `scripts/release-sbom.sh` (binary and image)
4. Keyless-signs the binary, checksums, SBOMs, and image-digest file
5. Pushes `ghcr.io/contextualwisdomlab/waf-ids-ai-soc:vX.Y.Z` and records
   the content digest in `IMAGE-DIGEST.txt`
6. Keyless-signs the image **by digest** and attests the image SBOM
7. Attaches GitHub artifact attestations (SLSA provenance + SBOM)
8. Creates the GitHub Release **only after** signatures succeed

GHCR tags are aliases. Promotion authority is the digest plus signatures,
not the tag. There is no moving `latest` tag.

Operators verify a binary with:

```bash
# SHA256SUMS records basenames only, so this works next to the download
sha256sum -c SHA256SUMS
# or: shasum -a 256 -c SHA256SUMS

cosign verify-blob \
  --bundle waf-ids-ai-soc-linux-x86_64.sigstore.json \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github.com/ContextualWisdomLab/wardnet/.github/workflows/release.yml@refs/tags/v' \
  waf-ids-ai-soc-linux-x86_64

gh attestation verify waf-ids-ai-soc-linux-x86_64 \
  --repo ContextualWisdomLab/wardnet
```

Operators verify the image with:

```bash
ref="$(cat IMAGE-DIGEST.txt)"   # ghcr.io/...@sha256:...
cosign verify \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github.com/ContextualWisdomLab/wardnet/.github/workflows/release.yml@refs/tags/v' \
  "$ref"
cosign verify-attestation --type spdxjson \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github.com/ContextualWisdomLab/wardnet/.github/workflows/release.yml@refs/tags/v' \
  "$ref"
```

Tampered bytes, a substituted digest, or a tag that no longer matches
`IMAGE-DIGEST.txt` fail verification. Do not promote a tag whose digest
changed.

## Promotion

1. Tag from the merge commit on `main`: `git tag -a vX.Y.Z -m "wardnet vX.Y.Z"`
2. `git push origin vX.Y.Z`
3. Wait for the Release workflow
4. Point Kubernetes at the digest (not `latest`, not the tag alone):

```yaml
image: ghcr.io/contextualwisdomlab/waf-ids-ai-soc@sha256:<digest>
imagePullPolicy: IfNotPresent
```

The committed lab manifest still uses `ghcr.io/contextualwisdomlab/waf-ids-ai-soc:0.1.0`
until a tagged image exists; bump that pin in the same release PR as the tag.

## Rollback

1. Identify the previous GitHub Release tag and its `IMAGE-DIGEST.txt`
2. Set the Deployment image back to that digest
3. Confirm `/healthz` and `/api/commercial/readiness` on the rolled-back replica
4. Do not retag or overwrite an existing `v*` image

Declared rollback unit: one immutable digest. Remaining on #84: ephemeral
production-shaped deploy of the signed digest, admission that rejects
unsigned tags, and the coverage/attack evidence bundle.
