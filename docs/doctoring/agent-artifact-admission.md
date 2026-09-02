# Agent Artifact Admission research and standards traceability

Verified 2026-09-02. This note records the primary sources that justify the admission controller's trust boundary. It does not claim certification or conformance beyond the tests and controls present in Wardnet.

## Decision trace

| Wardnet control | External basis | Local evidence |
| --- | --- | --- |
| Treat model/web/tool text as untrusted input, not execution authority | NIST SP 800-218A extends SSDF practices to generative-AI systems and their development lifecycle | Issue #128 threat model; `InstallIntent` must independently satisfy policy |
| Require reviewed, exact artifact identity and digest | NIST SSDF 1.1 emphasizes protecting software and verifying integrity; SLSA 1.2 formalizes provenance/verified properties | `ApprovedArtifact`, exact version/registry/owner/SHA-256 matching |
| Keep provenance provider schemas outside the domain model | SLSA, Sigstore and TUF have independent schemas, trust roots and lifecycle rules | ADR-0012 and DDD architecture fitness test require adapters/ACLs |
| Bind an allow decision to immutable reviewed policy | TUF's signed metadata model and SLSA source/build provenance both separate producer evidence from consumer verification policy | immutable v0.1 `AdmissionPolicy`; deny-all default |
| Do not infer publisher trust from registry presence | Sigstore verifies signing identity, certificate trust and Rekor inclusion; registry naming alone is not that evidence | exact reviewed owner is a local policy assertion, not an inferred identity |
| Audit before returning allow; fail closed on audit outage | SSDF supply-chain controls require protected evidence and traceable release/security practices; append-before-response prevents an unaudited authorization gap | `append_before_response`; `audit_unavailable` => block/503 |
| Structured argv; no shell command strings or runtime evaluation | SSDF least-functionality and secure-development principles; removes a command-injection interpretation layer | command-shape invariants in `policy.rs` |
| Reject alternate pip package sources and install roots | pip 26.2.1 documents `-i`/`--index-url` and `-f`/`--find-links` as package-source controls and `-t`/`--target`, `--root`, and `--prefix` as installation-location controls | `requests_alternate_trust_root`, `requests_alternate_install_root`, and attached-short-option hostile regressions |
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

### pip command trust and installation roots

The current stable pip 26.2.1 command reference defines `-i`/`--index-url` and `-f`/`--find-links` as inputs that change where package candidates are obtained. It also defines `-t`/`--target`, `--root`, and `--prefix` as controls that redirect where installation output is placed. Those are capability-expanding inputs relative to a reviewed artifact/registry/workspace intent, so Wardnet rejects them rather than silently widening an approved install. The parser recognizes both the documented short-option identity and attached short-option values; the latter is treated fail-closed because otherwise a short spelling can evade a policy that already forbids its long-form capability.

### npm command safety

npm documents `ignore-scripts` as a Boolean configuration with default `false`; when true, lifecycle scripts from package manifests are not executed. Wardnet's admission contract therefore requires the explicit safe token and rejects contradictory Boolean spellings in the same argv rather than attempting to reproduce npm's full precedence parser. This is deliberately fail-closed: the controller proves that the submitted command cannot negate the required safety flag before execution, while the executor and quarantine runtime remain responsible for environment and filesystem isolation.

## APA 7 references

Booth, H., Souppaya, M., Vassilev, A., Ogata, M., Stanley, M., & Scarfone, K. (2024). *Secure software development practices for generative AI and dual-use foundation models: An SSDF community profile (NIST SP 800-218A).* National Institute of Standards and Technology. https://doi.org/10.6028/NIST.SP.800-218A

National Institute of Standards and Technology. (2022). *Secure software development framework (SSDF) version 1.1: Recommendations for mitigating the risk of software vulnerabilities (NIST SP 800-218).* https://doi.org/10.6028/NIST.SP.800-218

National Institute of Standards and Technology. (2026). *Secure Software Development Framework: Publications.* https://csrc.nist.gov/Projects/ssdf/publications

pip developers. (2026). *pip install: pip documentation v26.2.1.* https://pip.pypa.io/en/stable/cli/pip_install/

npm, Inc. (2026). *Config: ignore-scripts.* https://docs.npmjs.com/using-npm/config/

SLSA Community. (2025). *SLSA specification: Version 1.2.* https://slsa.dev/spec/v1.2/

Sigstore. (2026). *Overview.* https://docs.sigstore.dev/

Sigstore. (2026). *Security model.* https://docs.sigstore.dev/about/security/

The Update Framework. (2026). *Specification.* https://theupdateframework.io/spec/

## Evidence limitations

Exact SHA-256 equality detects byte changes but does not establish publisher identity, build integrity or source review. An allow receipt is consequently a Wardnet policy decision, not a general authenticity certificate. Remote attestation, transparency-log verification and metadata freshness/rollback protection remain future adapter responsibilities and must fail closed when introduced.