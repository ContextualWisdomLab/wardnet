# Agent Artifact Admission research and standards traceability

Verified 2026-09-02. This note records the primary sources that justify the admission controller's trust boundary. It does not claim certification or conformance beyond the tests and controls present in Wardnet.

## Decision trace

| Wardnet control | External basis | Local evidence |
| --- | --- | --- |
| Treat model/web/tool text as untrusted input, not execution authority | NIST SP 800-218A extends SSDF practices to generative-AI systems and their development lifecycle | Issue #128 threat model; `InstallIntent` must independently satisfy policy |
| Require reviewed, exact artifact identity and digest | NIST SSDF 1.1 emphasizes protecting software and verifying integrity; SLSA 1.2 formalizes provenance/verified properties | `ApprovedArtifact`, exact version/registry/owner/SHA-256 matching |
| Bind the submitted package-manager executable to the reviewed artifact ecosystem | npm documents `<name>@<version>` install operands and Cargo documents `crate[@version]`; the same token shape therefore cannot establish which registry ecosystem an approval authorizes | `artifact_ecosystem_matches_executable`; `ecosystem_binding_contract.rs` cross-ecosystem RED plus same-ecosystem Cargo control |
| Keep provenance provider schemas outside the domain model | SLSA, Sigstore and TUF have independent schemas, trust roots and lifecycle rules | ADR-0012 and DDD architecture fitness test require adapters/ACLs |
| Bind an allow decision to immutable reviewed policy | TUF's signed metadata model and SLSA source/build provenance both separate producer evidence from consumer verification policy | immutable v0.1 `AdmissionPolicy`; deny-all default |
| Do not infer publisher trust from registry presence | Sigstore verifies signing identity, certificate trust and Rekor inclusion; registry naming alone is not that evidence | exact reviewed owner is a local policy assertion, not an inferred identity |
| Audit before returning allow; fail closed on audit outage | SSDF supply-chain controls require protected evidence and traceable release/security practices; append-before-response prevents an unaudited authorization gap | `append_before_response`; `audit_unavailable` => block/503 |
| Structured argv; no shell command strings or runtime evaluation | SSDF least-functionality and secure-development principles; removes a command-injection interpretation layer | command-shape invariants in `policy.rs` |
| Reject alternate pip package sources and install roots | pip 26.2.1 documents `-i`/`--index-url` and `-f`/`--find-links` as package-source controls and `-t`/`--target`, `--root`, and `--prefix` as installation-location controls | `requests_alternate_trust_root`, `requests_alternate_install_root`, and attached-short-option hostile regressions |
| Reject uv index and environment overrides | uv documents `--index`/`--default-index` as command-line package-index selectors, `--python` as an arbitrary target-environment selector, and `--system` as permission to mutate system Python | `requests_alternate_trust_root`, `requests_alternate_install_root`, `uv_index_selection_cannot_override_the_approved_registry`, and `uv_environment_selection_cannot_escape_the_broker_selected_install_root` |
| Reject Cargo source, install-root and inline configuration overrides | Cargo documents `--git`, `--path`, `--registry`, and `--index` as package-source selectors, `--root`/`install.root` as installation-root authorities, and `--config KEY=VALUE or PATH` as a command-line configuration override | `requests_alternate_trust_root`, `requests_alternate_install_root`, `cargo_source_selection_cannot_override_the_approved_registry`, and `cargo_inline_configuration_cannot_override_install_root` |
| Reject npm workspace scope overrides | npm documents `--workspace` as selecting named or path-addressed workspaces and `--workspaces` as running the command in all configured workspaces; install commands respect those selectors | `requests_alternate_install_root`; `npm_workspace_selection_cannot_expand_the_broker_selected_install_scope` |
| Require an unambiguous install-script suppression flag | npm documents `ignore-scripts` as a Boolean whose safe state is `true`; npm CLI Boolean options can be explicitly set back to false, so a contradictory argv must not satisfy admission merely because a safe token also appears | `has_unambiguous_boolean_safety_flag`; hostile `--ignore-scripts=false` and `--no-ignore-scripts` regressions |
| Loopback-only v0.1 | minimizes exposed trust boundary until authenticated transport is owned by a separate deployment layer | `validate_service_config` and service bind validation |

## Current status of referenced standards

### NIST SSDF

NIST SP 800-218, *Secure Software Development Framework (SSDF) Version 1.1*, remains the current final base SSDF publication. NIST SP 800-218 Rev. 1 / SSDF 1.2 was released as a draft on 2025-12-17 and is still listed by NIST as Draft as of this verification. Wardnet therefore treats 1.1 as binding guidance and 1.2 as informative until finalized.

NIST SP 800-218A, *Secure Software Development Practices for Generative AI and Dual-Use Foundation Models: An SSDF Community Profile*, is final (July 2024) and augments SSDF 1.1 for producers and acquirers of AI systems. It is relevant here because the threat originates when an AI-assisted development system converts untrusted information into software-development actions.

### SLSA

SLSA version 1.2 is the current Approved specification. It includes Source and Build tracks and recommended attestation formats. Wardnet does not claim a SLSA level merely because it checks digests; instead it can consume verified provenance properties through a future adapter and apply local admission policy to those properties.

### The Update Framework

The TUF specification page lists v1.0.33 as latest at verification time. TUF's metadata and role model are external trust evidence. A future TUF integration belongs in an adapter that translates verified target metadata into the minimum facts needed by the admission policy.

### Sigstore

Sigstore's verification flow validates an artifact signature, the signing identity bound into the certificate, the certificate chain/trust root, and Rekor transparency-log evidence. That makes it suitable as a future external publisher/integrity authority. Wardnet must not reduce those semantics to a registry-owner string or silently copy Sigstore DTOs into the domain kernel.

### Package-manager executable and ecosystem identity

An approved argv token is not by itself a package-registry identity. npm documents package install operands such as `name@version`; Cargo's current `cargo install` synopsis independently accepts `crate[@version]`. A reviewed token such as `ripgrep@1.2.3` can therefore be syntactically meaningful to both package managers while naming artifacts from different registries, publisher namespaces, and byte streams. Wardnet binds the executable family to the declared artifact ecosystem before exact artifact matching: npm-family commands may authorize only `npm`, pip/uv pip only `pypi`, Cargo only `cargo`, and Docker/Podman pulls only `oci`. The executor still verifies retrieved bytes/provenance; this admission check prevents an approval from being reinterpreted across ecosystems before execution.

### pip command trust and installation roots

The current stable pip 26.2.1 command reference defines `-i`/`--index-url` and `-f`/`--find-links` as inputs that change where package candidates are obtained. It also defines `-t`/`--target`, `--root`, and `--prefix` as controls that redirect where installation output is placed. Those are capability-expanding inputs relative to a reviewed artifact/registry/workspace intent, so Wardnet rejects them rather than silently widening an approved install. The parser recognizes both the documented short-option identity and attached short-option values; the latter is treated fail-closed because otherwise a short spelling can evade a policy that already forbids its long-form capability.

### uv package indexes and install environments

uv's package-index documentation states that command-line indexes take precedence over configured indexes and exposes `--index` and `--default-index` as index-selection controls. Its environment documentation states that `uv pip install --python /path/to/python` can install into an arbitrary environment and that `--system` opts into modifying system Python. Those controls change the trust root or destination selected by the broker-reviewed install intent. Wardnet therefore blocks them instead of assuming that an approved artifact coordinate is sufficient after the submitted command changes where candidates are obtained or where they are installed.

### Cargo package sources and install configuration

Cargo's `cargo install` documentation states that crates.io is the default package source while `--git`, `--path`, and `--registry` change that source; it separately exposes `--index` as a registry-index URL. The same command defines install-root precedence through `--root`, `CARGO_INSTALL_ROOT`, `install.root`, `CARGO_HOME`, then the default Cargo home, and Cargo's common options define `--config KEY=VALUE or PATH` as a command-line configuration override. Wardnet therefore rejects submitted source selectors (`--git`, `--path`, `--registry`, `--index`), `--root`, and `--config`: the reviewed artifact coordinate and destination remain the admission authority instead of being silently replaced by command arguments. The executor or quarantine runtime may establish controlled Cargo configuration outside this submitted argv boundary.

### npm workspace and command safety

npm's current workspace documentation defines workspaces as nested packages in the local filesystem and shows that install commands respect workspace selection. The `workspace` option can name a workspace, point at a workspace directory, or point at a parent directory that selects nested workspaces; `workspaces` enables the command across all configured workspaces. Those selectors change the submitted command's filesystem/package scope relative to the broker-selected workspace intent, so Wardnet rejects `--workspace`, `--workspace=...`, `--workspaces`, and the enabled `--workspaces=true` spelling instead of allowing an approved artifact to authorize writes across a caller-selected workspace set.

npm also documents `ignore-scripts` as a Boolean configuration with default `false`; when true, lifecycle scripts from package manifests are not executed. Wardnet's admission contract therefore requires the explicit safe token and rejects contradictory Boolean spellings in the same argv rather than attempting to reproduce npm's full precedence parser. This is deliberately fail-closed: the controller proves that the submitted command cannot negate the required safety flag before execution, while the executor and quarantine runtime remain responsible for environment and filesystem isolation.

## APA 7 references

Astral Software, Inc. (2026). *Package indexes: uv documentation.* https://docs.astral.sh/uv/configuration/indexes/

Astral Software, Inc. (2026). *Using environments: uv documentation.* https://docs.astral.sh/uv/pip/environments/

Booth, H., Souppaya, M., Vassilev, A., Ogata, M., Stanley, M., & Scarfone, K. (2024). *Secure software development practices for generative AI and dual-use foundation models: An SSDF community profile (NIST SP 800-218A).* National Institute of Standards and Technology. https://doi.org/10.6028/NIST.SP.800-218A

National Institute of Standards and Technology. (2022). *Secure Software Development Framework (SSDF) Version 1.1: Recommendations for Mitigating the Risk of Software Vulnerabilities (NIST SP 800-218).* https://doi.org/10.6028/NIST.SP.800-218

National Institute of Standards and Technology. (2026). *Secure Software Development Framework: Publications.* https://csrc.nist.gov/Projects/ssdf/publications

npm, Inc. (2026). *Config: ignore-scripts.* https://docs.npmjs.com/using-npm/config/

npm, Inc. (2026). *Workspaces.* https://docs.npmjs.com/misc/workspaces/

npm, Inc. (2026). *npm install.* https://docs.npmjs.com/cli/v10/commands/npm-install/

pip developers. (2026). *pip install: pip documentation v26.2.1.* https://pip.pypa.io/en/stable/cli/pip_install/

Rust Project Developers. (2026). *cargo install: The Cargo Book.* https://doc.rust-lang.org/stable/cargo/commands/cargo-install.html

Rust Project Developers. (2026). *Configuration: The Cargo Book.* https://doc.rust-lang.org/cargo/reference/config.html

SLSA Community. (2025). *SLSA specification: Version 1.2.* https://slsa.dev/spec/v1.2/

Sigstore. (2026). *Overview.* https://docs.sigstore.dev/

Sigstore. (2026). *Security model.* https://docs.sigstore.dev/about/security/

The Update Framework. (2026). *Specification.* https://theupdateframework.io/spec/

## Evidence limitations

Exact SHA-256 equality detects byte changes but does not establish publisher identity, build integrity or source review. An allow receipt is consequently a Wardnet policy decision, not a general authenticity certificate. Remote attestation, transparency-log verification and metadata freshness/rollback protection remain future adapter responsibilities and must fail closed when introduced.
