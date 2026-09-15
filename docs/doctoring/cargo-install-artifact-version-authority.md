# Cargo install artifact-version authority

Verified 2026-09-04 against the current Cargo Book. This note records the narrow evidence behind Wardnet's Agent Artifact Admission rule for Cargo installs; it does not make Wardnet a Cargo resolver or execution authority.

## Problem

`InstallIntent.artifacts` and `AdmissionPolicy.approved_artifacts` already carry an exact reviewed Cargo package name, version, registry, owner, SHA-256, and argv operand. Cargo independently permits version selection through both `crate@version` operands and `--vers` / `--version`. If Wardnet accepted a bare crate operand plus a caller-selected version flag, or accepted `crate@other-version` while the reviewed coordinate named another version, the executable could select artifact bytes outside the reviewed identity even though the policy object still reported the approved version.

## Decision

For the current Cargo admission profile:

- the artifact operand must be exactly `name@version` for the reviewed Cargo coordinate;
- caller-supplied `--vers` and `--version` are rejected as unapproved artifact-identity selectors;
- source, feature, target, profile, binary/example, install-root, and inline-config selectors remain separately fail-closed under their existing controls;
- Wardnet still does not fetch, build, install, or verify retrieved crate bytes. The executor remains responsible for digest/provenance verification before execution.

This is intentionally narrower than reproducing Cargo's resolver. The admission boundary compares a submitted capability to reviewed authority and rejects alternate selection authority.

## RED → GREEN evidence

RED `4484acd2f7c9609ab16ddc68a748cac6cd49b51d` added hostile cases demonstrating that a reviewed `1.2.3` coordinate could otherwise be paired with `--version=9.9.9`, `--vers=9.9.9`, or a mismatched `crate@9.9.9` operand. The production repair in the current lineage routes these conditions through the existing `artifact_not_approved` fail-closed result.

## Primary-source trace

The Cargo Book documents the `cargo install [options] crate[@version]…` syntax and separately documents `--vers version` / `--version version` as version selectors. It states that a version with no requirement operator in MAJOR.MINOR.PATCH form installs exactly that version. This makes version selection part of artifact identity rather than an inert presentation option.

## APA 7 reference

Rust Project Developers. (2026). *cargo install—The Cargo Book*. Retrieved September 4, 2026, from https://doc.rust-lang.org/cargo/commands/cargo-install.html
