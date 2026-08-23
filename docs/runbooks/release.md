# Release, promotion, and rollback

Issue #84 first slice. IEEE/ACM PDFs are not redistributed. Buyer evidence
path: `GET /api/commercial/evidence-manifest` lists this runbook.

## Immutable artifacts

A git tag `vX.Y.Z` starts `.github/workflows/release.yml`, which:

1. Builds `waf-ids-ai-soc` with `cargo build --locked --release`
2. Writes `SHA256SUMS` via `scripts/release-checksums.sh`
3. Creates a GitHub Release with the Linux binary and checksums
4. Pushes an immutable image `ghcr.io/contextualwisdomlab/waf-ids-ai-soc:vX.Y.Z`
   (no moving `latest` tag)

Operators verify a binary with:

```bash
scripts/release-checksums.sh waf-ids-ai-soc-linux-x86_64
# compare to SHA256SUMS on the GitHub Release
```

## Promotion

1. Tag from the merge commit on `main`: `git tag -a vX.Y.Z -m "wardnet vX.Y.Z"`
2. `git push origin vX.Y.Z`
3. Wait for the Release workflow
4. Point Kubernetes at the tag (not `latest`):

```yaml
image: ghcr.io/contextualwisdomlab/waf-ids-ai-soc:vX.Y.Z
imagePullPolicy: IfNotPresent
```

The committed lab manifest still uses `ghcr.io/contextualwisdomlab/waf-ids-ai-soc:0.1.0`
until a tagged image exists; bump that pin in the same release PR as the tag.

## Rollback

1. Identify the previous GitHub Release tag (for example `v0.1.0`)
2. Set the Deployment image back to that tag
3. Confirm `/healthz` and `/api/commercial/readiness` on the rolled-back replica
4. Do not retag or overwrite an existing `v*` image

Declared rollback unit: one immutable tag. Remaining: keyless cosign/SBOM
attestation on the same tag (SLSA provenance).
