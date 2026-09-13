# Cargo install overwrite and tracking authority

Verified 2026-09-04 against the current Cargo Book. This note records the narrow evidence behind Wardnet's Agent Artifact Admission rule for Cargo mutation semantics; it does not make Wardnet an installer or filesystem authority.

## Problem

A reviewed Cargo artifact coordinate authorizes one exact package identity. It does not authorize the caller to widen the install's mutation semantics after review. Cargo documents `-f` / `--force` as authority to overwrite existing crates or binaries, including binaries owned by another package. Cargo also documents `--no-track` as disabling installed-package metadata and Cargo's protection against concurrent install invocations. Those effects can overwrite an existing executable or remove collision/concurrency safeguards without changing the submitted package coordinate.

For an agent-facing pre-execution admission boundary, treating those switches as ordinary presentation flags would let untrusted argv acquire filesystem mutation authority absent from the reviewed policy.

## Decision

For the current Cargo admission profile:

- caller-supplied `-f` / `--force` fails closed as `artifact_not_approved`;
- caller-supplied `--no-track` fails closed as `artifact_not_approved`;
- the rule applies only to `cargo install`; other Cargo commands remain outside the supported command grammar;
- Wardnet does not decide which existing binary may be replaced, manage the Cargo install root, execute Cargo, or provide runtime concurrency isolation. Any future overwrite/metadata exception requires an explicit versioned policy capability and downstream executor controls.

The existing exact package/version/source/build/install-root controls remain independent. This rule adds no Cargo resolver behavior; it simply prevents the caller from adding destructive or tracking-bypass authority that is absent from the reviewed intent.

## RED → GREEN evidence

RED `4c5883decdfb89c8197fd5183cff948d6d2b34a2` adds hostile `--force`, `-f`, and `--no-track` requests to the approved Cargo-install contract. The pre-repair evaluator had no rule that classified those switches as unreviewed authority. The production repair is split into helper introduction `76823b8858f33655d4c4107cd2b820fd5fb2572a` and admission wiring `c35f646db12104bcd8bc63c5773c0c62621ccc34`, which routes all three forms through the existing `artifact_not_approved` fail-closed result.

Repository-hosted execution remains required on the exact current head because the organization runner control plane is presently queue-starved; predecessor check conclusions do not transfer.

## Primary-source trace

The Cargo Book states that `-f` / `--force` forces overwriting existing crates or binaries and can be used when another package already installed a binary with the same name. It also states that `--no-track` disables the installed-package metadata file and Cargo's ability to protect against multiple concurrent install invocations. Both therefore alter mutation/collision semantics rather than merely formatting output.

## APA 7 reference

Rust Project Developers. (2026). *cargo install—The Cargo Book*. Retrieved September 4, 2026, from https://doc.rust-lang.org/cargo/commands/cargo-install.html
