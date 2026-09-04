# OCI registry transport and authentication trust authority

Verified 2026-09-04. This note records why Wardnet's Agent Artifact Admission boundary rejects caller-selected Podman registry TLS weakening, certificate replacement, or registry-principal overrides. It is an admission-policy control only; Wardnet does not fetch images or take over hostile execution from `quarantine-sandbox-runtime`.

## Problem

An approved OCI coordinate binds an HTTPS registry URL and exact artifact identity, but Podman's pull command exposes transport and authentication options that can change how that registry is reached and which principal is used. Current Podman documentation states that `--tls-verify=false` disables certificate verification, `--cert-dir=path` selects certificates used to connect to the registry, `--authfile=path` selects registry authentication state, and `--creds=username[:password]` supplies the registry principal directly.

Before these repairs, a structured intent such as `podman pull --tls-verify=false IMAGE@sha256:DIGEST`, `podman pull --cert-dir=/unreviewed IMAGE@sha256:DIGEST`, `podman pull --authfile=/agent-controlled.json IMAGE@sha256:DIGEST`, or `podman pull --creds=agent-user:secret IMAGE@sha256:DIGEST` could still satisfy Wardnet's exact artifact, manifest, executable, and digest checks. The caller could therefore weaken transport trust or substitute registry authentication authority without a corresponding policy grant. Digest verification downstream remains necessary, but it does not make caller-controlled registry transport or identity part of the reviewed admission authority.

## Decision

Wardnet classifies Podman `--cert-dir`, `--authfile`, and `--creds` overrides plus false values of `--tls-verify` as `alternate_trust_root` and blocks the install intent. Go/Podman-compatible false spellings represented by `false`, `f`, and `0` are treated equivalently, case-insensitively. Explicit `--tls-verify=true` remains compatible because it does not weaken the reviewed HTTPS registry trust. Registry credentials must be supplied by the downstream execution/deployment authority through a separately governed boundary, not selected by untrusted install argv.

The control is implemented in the bounded `oci_transport` domain predicate and composed into the existing admission result. It does not add a new public reason code, read credential files, authenticate to a registry, or duplicate registry transport/runtime verification logic.

## Executable evidence

- RED `186be292eea13a8cc97c10e09208a5360a2a5996` introduces the hostile Podman TLS-disable and custom certificate-directory cases; `7725ae8a8583f53c78c02df7296069dc4c270b37` extends the RED across accepted false spellings while retaining a `--tls-verify=true` allow control.
- Causal repair `b7b13e5db6997bb0ccdddea000ededd2a7b4cdb6` adds the bounded OCI transport-trust predicate, and GREEN composition `c4cb57312dc0bf2972ad7ae61e3c526b49c5217f` maps it to the existing `alternate_trust_root` fail-closed decision.
- Authentication-authority RED `400c53265f21d684ab06232536b50341b5d524c0` adds attached `--authfile` and `--creds` hostile cases that previously remained syntactically admissible; causal GREEN `3eade5d41c50d1ad4e48118014c50acf5d8f3793` extends the same bounded predicate to reject caller-selected registry authentication sources/principals.
- Architecture fitness `7c833b6c4fc77c1ad17c03b48169addfb5328c5b` places `oci_transport.rs` under the same dependency-direction contract as the other admission-domain sources.

Exact-current-head repository, security, coverage, and review execution remains required before integration. Queued or predecessor evidence is not GREEN.

## APA 7 reference

Podman Project. (2026). *podman-pull — Pull an image from a registry*. Podman documentation. https://docs.podman.io/en/stable/markdown/podman-pull.1.html
