# OCI registry TLS trust authority

Verified 2026-09-04. This note records why Wardnet's Agent Artifact Admission boundary rejects caller-selected Podman registry TLS weakening or certificate-directory replacement. It is an admission-policy control only; Wardnet does not fetch images or take over hostile execution from `quarantine-sandbox-runtime`.

## Problem

An approved OCI coordinate binds an HTTPS registry URL and exact artifact identity, but Podman's pull command exposes transport options that can change how that registry identity is authenticated. Current Podman documentation states that `--tls-verify=false` disables certificate verification when contacting registries and that `--cert-dir=path` selects certificates used to connect to the registry.

Before this repair, a structured intent such as `podman pull --tls-verify=false IMAGE@sha256:DIGEST` or `podman pull --cert-dir=/unreviewed IMAGE@sha256:DIGEST` could still satisfy Wardnet's exact artifact, manifest, executable, and digest checks. The caller could therefore weaken or replace the TLS trust used for the approved registry without a corresponding policy grant. Digest verification downstream remains necessary, but it does not make caller-controlled registry authentication part of the reviewed admission authority.

## Decision

Wardnet classifies Podman `--cert-dir` overrides and false values of `--tls-verify` as `alternate_trust_root` and blocks the install intent. Go/Podman-compatible false spellings represented by `false`, `f`, and `0` are treated equivalently, case-insensitively. Explicit `--tls-verify=true` remains compatible because it does not weaken the reviewed HTTPS registry trust.

The control is implemented in the bounded `oci_transport` domain predicate and composed into the existing admission result. It does not add a new public reason code, does not select certificates itself, and does not duplicate registry transport or runtime verification logic.

## Executable evidence

- RED `186be292eea13a8cc97c10e09208a5360a2a5996` introduces the hostile Podman TLS-disable and custom certificate-directory cases; `7725ae8a8583f53c78c02df7296069dc4c270b37` extends the RED across accepted false spellings while retaining a `--tls-verify=true` allow control.
- Causal repair `b7b13e5db6997bb0ccdddea000ededd2a7b4cdb6` adds the bounded OCI transport-trust predicate, and GREEN composition `c4cb57312dc0bf2972ad7ae61e3c526b49c5217f` maps it to the existing `alternate_trust_root` fail-closed decision.
- Architecture fitness `7c833b6c4fc77c1ad17c03b48169addfb5328c5b` places `oci_transport.rs` under the same dependency-direction contract as the other admission-domain sources.

Exact-current-head repository, security, coverage, and review execution remains required before integration. Queued or predecessor evidence is not GREEN.

## APA 7 reference

Podman Project. (2026). *podman-pull — Pull an image from a registry*. Podman documentation. https://docs.podman.io/en/latest/markdown/podman-pull.1.html
