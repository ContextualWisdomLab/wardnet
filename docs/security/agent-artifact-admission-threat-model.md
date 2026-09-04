| Policy/provider schema coupling | Sigstore/TUF/SLSA DTO changes alter domain semantics implicitly | Translate provider evidence at explicit adapters/ACLs; domain depends only on stable admission concepts | Reject unsupported evidence until an accepted adapter exists |
| Cross-context authority leakage | Main gateway, SIEM exporter or orchestrator mutates admission policy by reaching into internals | Published API/package contract only; no foreign application-table access; no provider SDK in domain modules | Integration rejected by architecture fitness gate |
| Confused transport vs policy denial | Downstream treats a policy block as network failure and retries/works around it | Valid policy denials are successful admission responses with `decision=block`; transport/config/audit failures use HTTP errors | Stable receipt semantics |

## Abuse cases

A document can legitimately mention `npm install`, a package name, a CVE, or a URL. Those strings are not executable instructions at this boundary. An agent must first construct a structured intent, and the intent must independently satisfy policy. A package with valid Sigstore/SLSA evidence is still not locally authorized unless the reviewed policy allows its exact coordinates. Conversely, an approved coordinate without the required digest or provenance remains blocked.

The controller must not repair typos, prepend package scopes, infer maintainers, search for a similarly named package, downgrade HTTPS, transform a blocked command into an allowed one, reinterpret an approved workspace install as permission to write into a global/user/alternate install root or a caller-selected workspace/project set, reinterpret an approved Cargo source digest as permission to select an unreviewed feature set/binary/example/target/profile, reinterpret an approved PyPI coordinate as permission for pip or uv to select an unreviewed target platform/build variant or resolve undeclared transitive artifacts, reinterpret an approved registry coordinate as permission to fetch from an alternate index, registry, Git repository, local path, caller-selected npm configuration file, executable pnpmfile hook, caller-selected registry authentication file/principal, or caller-selected image-decryption key/passphrase, weaken or replace registry TLS certificate validation, accept a standalone `--` that creates a second option-parsing boundary, or let a package-manager-specific opaque configuration channel override reviewed source/safety/destination semantics. Any such behavior would convert untrusted input into authority or widen the reviewed command capability.

## Operational security invariants

- `0.0.0.0`, `::`, non-loopback addresses and port `0` are invalid service configuration for v0.1.
- The administrator token is loaded from the configured credentials file. It is never returned in health, error or audit payloads.
- The deny-all example configuration is safe to start without granting package authority.
- Audit records are append-only from this process's point of view. Corruption, write failure or task failure cannot be converted into an allow response.
- Policy is immutable for the lifetime of the v0.1 process. Runtime mutation requires a future explicit policy-lifecycle aggregate and authorization contract; it must not be smuggled into the current HTTP adapter.
- Domain modules remain independent of Axum, Tokio, filesystem paths, provider SDKs and concrete storage adapters. `ddd_architecture_contract.rs` is the executable fitness gate.
- Package-manager source, destination, environment, workspace-scope, build-variant, dependency-cardinality, parser-boundary, trust/secret authority and opaque runtime-configuration overrides are admission capability changes, not ordinary argument detail. The admission kernel rejects the standalone `--` option terminator, explicit alternate trust roots/sources, alternate install roots/environments/workspace scopes, unbound Cargo feature/output/target/profile selectors, unbound pip/uv target and source-build selectors, npm caller-selected user/global configuration files and registry TLS trust overrides, Podman caller-selected registry authentication files/principals and image-decryption key/passphrase material, and pnpm's submitted dotted configuration channel. Admitted pip, pip3 and `uv pip install` commands require exact `--no-deps` so the resolver cannot add artifacts missing from the reviewed intent. Admitted pnpm installs require `--ignore-pnpmfile` because pnpm documents that `--ignore-scripts` does not suppress pnpmfile hooks. The downstream execution broker/quarantine runtime still owns actual artifact retrieval/decryption verification, secret/key access, filesystem, mount, process and network isolation.

## Residual risk and future adapters

SHA-256 equality proves byte identity only when the execution path independently verifies the retrieved bytes against the reviewed digest; the admission controller itself validates the requested digest against policy but does not retrieve or hash package bytes. Registry and owner strings in a reviewed policy are local assertions until backed by independently verified provenance. Future Sigstore, TUF and SLSA support should verify external evidence and translate only the verified properties needed by the admission domain. The execution broker/quarantine path must preserve the admitted artifact identity and verify retrieved bytes before installation or execution; Wardnet must not claim that an allow receipt alone proves downloaded-byte integrity. The controller also does not sandbox an allowed installer, authenticate to registries, resolve secret handles, or decrypt images; those remain separately governed downstream authorities. Rejecting explicit parser/source/root/environment/workspace/configuration/build-variant/dependency-cardinality/trust/secret overrides and suppressing local pnpmfile hooks narrows the command capability but does not substitute for runtime isolation or secret-management boundaries.

## Primary references

- Astral Software, Inc. (2026). *uv CLI reference: uv pip install.* https://docs.astral.sh/uv/reference/cli/
- National Institute of Standards and Technology. (2022). *Secure Software Development Framework (SSDF) Version 1.1: Recommendations for Mitigating the Risk of Software Vulnerabilities (NIST SP 800-218).* https://doi.org/10.6028/NIST.SP.800-218
- Booth, H., Souppaya, M., Vassilev, A., Ogata, M., Stanley, M., & Scarfone, K. (2024). *Secure software development practices for generative AI and dual-use foundation models: An SSDF community profile (NIST SP 800-218A).* National Institute of Standards and Technology. https://doi.org/10.6028/NIST.SP.800-218A
- npm, Inc. (2026). *Config.* https://docs.npmjs.com/using-npm/config/
- npm, Inc. (2026). *Workspaces.* https://docs.npmjs.com/misc/workspaces/
- npm, Inc. (2026). *npm install.* https://docs.npmjs.com/cli/install/
- npm, Inc. (2026). *npm exec.* https://docs.npmjs.com/cli/npm-exec/
- pip developers. (2026). *pip install.* https://pip.pypa.io/en/latest/cli/pip_install/
- pip developers. (2026). *Repeatable installs.* https://pip.pypa.io/en/latest/topics/repeatable-installs/
- pnpm contributors. (2026). *.pnpmfile.mjs.* https://pnpm.io/pnpmfile
- pnpm contributors. (2026). *Build settings.* https://pnpm.io/settings/build
- pnpm contributors. (2026). *CLI configuration override parser* [Source code, commit dc44db593500193cdb499769fac8f173fe25e501]. GitHub. https://github.com/pnpm/pnpm/blob/dc44db593500193cdb499769fac8f173fe25e501/pnpm/crates/cli/src/config_overrides.rs
- pnpm contributors. (2026). *CLI startup and `--config.<key>=<value>` extraction* [Source code, commit dc44db593500193cdb499769fac8f173fe25e501]. GitHub. https://github.com/pnpm/pnpm/blob/dc44db593500193cdb499769fac8f173fe25e501/pnpm/crates/cli/src/lib.rs
- Podman Project. (2026). *podman-pull — Pull an image from a registry.* https://docs.podman.io/en/stable/markdown/podman-pull.1.html
- The Rust Project. (2026). *cargo install — The Cargo Book.* https://doc.rust-lang.org/cargo/commands/cargo-install.html
- SLSA Community. (2025). *SLSA specification, version 1.2.* https://slsa.dev/spec/v1.2/
- The Update Framework. (2026). *Specification, version 1.0.33.* https://theupdateframework.io/spec/
- Sigstore. (2026). *Sigstore documentation: Overview and security model.* https://docs.sigstore.dev/ ; https://docs.sigstore.dev/about/security/

NIST SP 800-218 Rev. 1 / SSDF 1.2 is still a draft as of this document's 2026-09-02 verification and is tracked as informative rather than binding: https://csrc.nist.gov/Projects/ssdf/publications
