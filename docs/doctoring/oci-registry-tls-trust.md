# OCI registry transport, authentication, and decryption authority

Verified 2026-09-04. This note records why Wardnet's Agent Artifact Admission boundary rejects caller-selected Podman registry TLS weakening, certificate replacement, registry-principal overrides, and image decryption material. It is an admission-policy control only; Wardnet does not fetch or decrypt images and does not take over hostile execution from `quarantine-sandbox-runtime`.

## Problem

An approved OCI coordinate binds an HTTPS registry URL and exact artifact identity, but Podman's pull command exposes transport, authentication, and decryption options that can introduce additional authority. Current Podman documentation states that `--tls-verify=false` disables certificate verification, `--cert-dir=path` selects certificates used to connect to the registry, `--authfile=path` selects registry authentication state, `--creds=username[:password]` supplies the registry principal directly, and `--decryption-key=key[:passphrase]` selects keys or certificates for image decryption and can carry a passphrase in the argument.

Before these repairs, otherwise exact structured intents could combine an approved digest with caller-selected TLS trust, registry credentials, or decryption material. Attached option forms begin with `-`, so Wardnet's artifact-operand accounting correctly ignored them as positional artifact names; without an explicit trust/secret-authority predicate, however, those options could survive exact artifact, manifest, executable, and digest checks. Digest verification downstream remains necessary, but it does not make caller-controlled transport, authentication, local key material, or passphrases part of reviewed admission authority.

## Decision

Wardnet classifies Podman `--cert-dir`, `--authfile`, `--creds`, and `--decryption-key` overrides plus false values of `--tls-verify` as `alternate_trust_root` and blocks the install intent. Go/Podman-compatible false spellings represented by `false`, `f`, and `0` are treated equivalently, case-insensitively. Explicit `--tls-verify=true` remains compatible because it does not weaken reviewed HTTPS registry trust.

Registry credentials and image-decryption secrets must be supplied by separately governed downstream execution/deployment/secret boundaries, not selected by untrusted install argv. Wardnet does not read an authfile or key, authenticate to a registry, decrypt an image, or copy secret-management/runtime behavior into the admission domain.

The control is implemented in the bounded `oci_transport` domain predicate and composed into the existing admission result. It intentionally reuses the stable `alternate_trust_root` reason because these options introduce caller-selected trust/secret authority outside the reviewed artifact contract; a future versioned domain contract may split machine-readable subcategories without weakening the fail-closed behavior.

## Executable evidence

- RED `186be292eea13a8cc97c10e09208a5360a2a5996` introduces hostile Podman TLS-disable and custom certificate-directory cases; `7725ae8a8583f53c78c02df7296069dc4c270b37` extends the RED across accepted false spellings while retaining a `--tls-verify=true` allow control.
- Causal repair `b7b13e5db6997bb0ccdddea000ededd2a7b4cdb6` adds the bounded OCI transport-trust predicate, and GREEN composition `c4cb57312dc0bf2972ad7ae61e3c526b49c5217f` maps it to the existing `alternate_trust_root` fail-closed decision.
- Authentication-authority RED `400c53265f21d684ab06232536b50341b5d524c0` adds attached `--authfile` and `--creds` hostile cases that previously remained syntactically admissible; causal GREEN `3eade5d41c50d1ad4e48118014c50acf5d8f3793` rejects caller-selected registry authentication sources/principals.
- Decryption-authority RED `d7aa94fc3846e0ed189f90b5525df03d1a62e3ee` adds an attached secret-bearing `--decryption-key=...:passphrase` hostile case; causal GREEN `261ecc20e280c3af45798cc396088260eb94ba50` rejects caller-selected image decryption key/passphrase material at the same bounded boundary.
- Architecture fitness `7c833b6c4fc77c1ad17c03b48169addfb5328c5b` places `oci_transport.rs` under the same dependency-direction contract as the other admission-domain sources.

Exact-current-head repository, security, coverage, and review execution remains required before integration. Queued or predecessor evidence is not GREEN.

## APA 7 reference

Podman Project. (2026). *podman-pull — Pull an image from a registry*. Podman documentation. https://docs.podman.io/en/stable/markdown/podman-pull.1.html
