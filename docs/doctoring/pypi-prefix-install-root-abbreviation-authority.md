# Direct pip prefix install-root abbreviation authority

Issue: #339  
Implementation lane: #340  
Canonical parent at RED: `#129@1c5f6217b1e52d3bcb25e29e113981bef4c524c0`

## Problem and boundary

Agent Artifact Admission already rejects canonical direct-pip install-root selectors and the verified `--target` long-option abbreviation language. Pinned pip also exposes `--prefix <dir>` and parses long options with Python `optparse` abbreviation semantics. On the reviewed install option surface, `--pref` is ambiguous with `--prefer-binary`, while `--prefi` is the shortest unambiguous prefix selecting `--prefix`.

Before this repair, an otherwise approved `pip install` or `pip3 install` carrying attached `--prefi=/tmp/wardnet-pip-prefix` remained `Allow`. The token begins with `-`, so positional artifact-cardinality checks did not independently reject the alternate install-root authority.

Wardnet owns only structured argv admission, stable reason codes, policy evidence, and SOC accountability for this decision. It does not create, resolve, mount, inspect, clean, or otherwise govern the effective destination. Filesystem/workspace/mount isolation and cleanup remain `quarantine-sandbox-runtime` authority.

## Test-first evidence

Exact test-only RED head `d4639c9b77a458b244241ebc78dedb22c13fdd74` executed in CI run `34649961884`, job `103429556651`. Checkout, Rust toolchain setup, and `cargo fmt --check` passed. `cargo test --locked --workspace` then failed at `pypi_prefix_abbreviation_authority_contract` because `pip --prefi=...` returned `Allow` where the contract required `Block`. The exact approved baseline remained admissible before the hostile argument was added.

The earlier head `66d015297ffddcfadd904ac57b164c19233491a4` failed only `cargo fmt --check` and is not semantic RED evidence.

## Minimum causal repair

The direct-pip install-root abbreviation classifier is extended only to the pinned parser-supported `--prefix` language from `--prefi` through canonical `--prefix`, while retaining the existing `--target` language. `--pref`, `--prefer-binary`, superstrings, and non-long-option spellings remain outside the prefix matcher. The behavior is not generalized to uv or other package managers.

The hostile contract exercises both `pip` and `pip3`, requires stable `alternate_install_root` evidence for accepted `--prefi=...`, and preserves the ambiguous `--pref=...` precision control. No pip subprocess or filesystem mutation is executed by the test.

Exact-head GREEN is intentionally not inferred from source inspection or predecessor runs. The implementation may integrate only after its unchanged exact head completes the repository-required CI/Fuzz and fresh review/thread acceptance.

## Decision record

- **Constraint:** preserve the reviewed package coordinate while denying caller-selected install-root authority.
- **Rejected:** treating every `--pref*` token as `--prefix`; this would invent semantics for the ambiguous `--pref` spelling.
- **Rejected:** copying Python `optparse` abbreviation behavior into a generic package-manager parser; that would exceed the pinned direct-pip authority surface.
- **Selected:** a bounded direct-pip matcher for the two verified install-root long-option families.
- **Risk:** upstream pip may change its option surface, changing abbreviation uniqueness. The matcher therefore remains pinned-source evidence and must be reverified when the authoritative pip parser pin changes.

## TRACEABILITY

Python Packaging Authority. (2026). *pip install command* (source pin `pypa/pip@2b28a816d043826f2ba10ff1d22ec3d94d2ed7c5`). `--prefix <dir>` selects an installation prefix.

Python Software Foundation. (2026). *optparse — Parser for command line options*. Python 3.14 documentation. Unambiguous long-option prefixes are accepted as abbreviations.

National Institute of Standards and Technology. (2022). *Secure Software Development Framework (SSDF) Version 1.1* (NIST SP 800-218). PW.8.

MITRE. (2025). *CWE-15: External Control of System or Configuration Setting*.
