# uv system certificate-store authority

Status: Proposed implementation evidence on Draft #289. This note is not protected or released truth until the effective delta reaches protected `main`.

## Decision

Wardnet treats caller-selected `uv pip install --system-certs` as an expansion of TLS trust authority and blocks it before execution with the existing stable `alternate_trust_root` reason. The reviewed uv install without this selector remains admissible.

The rule is executable-scoped. `--system-certs` is not added to the package-manager-wide forbidden flag set because the option grammar and meaning are owned by uv. Wardnet classifies only structured argv that is present in the admission intent; it does not infer the `UV_SYSTEM_CERTS` environment setting, enumerate native certificate stores, validate certificates, perform TLS, or make network calls.

`quarantine-sandbox-runtime` remains the canonical owner of effective runtime/environment/configuration containment. EgressWeave remains the canonical owner of executable outbound transport and TLS enforcement. Wardnet's receipt remains pre-execution admission evidence rather than runtime or transport proof.

## Problem and threat model

Astral's current uv CLI documents `--system-certs` for `uv pip install` as selecting the platform native certificate store instead of uv's bundled Mozilla roots. That is a material change in which certification authorities can authenticate the registry/proxy path even when the reviewed package name, version, registry URL, hash, dependency cardinality, and executable remain unchanged.

Before this repair, the Agent Artifact Admission classifier recognized explicit index, insecure-host, certificate-file, client-certificate, proxy/config and related authority selectors, but did not classify uv's native certificate-store selector. A reviewed artifact could therefore retain the same artifact coordinate while caller-controlled argv changed the effective root-of-trust source.

This is primarily an authority/configuration-selection defect. CWE-15 is the closest root-cause taxonomy because an external input controls a security-relevant configuration setting. CWE-295 is supporting threat context for why certificate trust configuration is security-sensitive; Wardnet does not claim that selecting a native store is itself proof of improper certificate validation.

## Alternatives considered

### Put `--system-certs` in the generic forbidden flag list

Rejected. That would make a uv-specific parser contract appear package-manager-neutral and could misclassify a future unrelated executable that happens to use the same spelling. The minimum rule is scoped to `executable == "uv"`.

### Preserve the older `--native-tls` CLI spelling

Rejected. Fresh current uv CLI documentation exposes `--system-certs`; it does not expose `--native-tls` as a command-line option. The uv settings reference retains `native-tls` only as a deprecated configuration setting in favor of `system-certs`. Wardnet does not invent or permanently preserve removed argv grammar without parser evidence.

### Inspect `UV_SYSTEM_CERTS` or the host certificate store inside Wardnet

Rejected. Environment resolution, platform store inspection, process execution and effective runtime configuration belong to the quarantine runtime boundary. Importing them would turn deterministic admission into ambient runtime inspection and duplicate canonical-owner responsibilities.

### Delegate the argv-visible selector entirely to EgressWeave

Rejected. EgressWeave owns executable transport enforcement, but Wardnet owns whether the structured install intent itself is admissible. An admission receipt must not state that a reviewed artifact install is allowed when its caller has also selected a different trust authority source.

## RED → repair evidence

Canonical parent #129 for this child is `6571224032bf081387426c50932f130922e0e2bc`.

Test-only #289 head `4e35ca8d158f8f8a2c8415b4252d3e2e9aa772d4` added only `crates/agent-artifact-admission/tests/uv_system_certificate_store_authority_contract.rs`; production policy source remained byte-identical to the parent. Hosted CI `34549284828`, rust job `103108565858`, acquired an Ubuntu 24.04 hosted runner, passed checkout, toolchain setup and `cargo fmt --check`, then ran `cargo test --locked --workspace`. The reviewed uv baseline control passed. The hostile test `uv_system_certificate_store_cannot_inherit_artifact_approval` failed at the admission assertion with `left: Allow`, `right: Block`. Existing suites shown before it, including the four uv keyring-provider contracts, passed. This is semantic RED, not runner, bootstrap or formatting noise.

Minimum causal repair `40d7365692aded7430dd6e4f781c40b96ea36a6f` changes only `requests_alternate_trust_root`: when the executable is uv, a structured `--system-certs` selector is classified as `alternate_trust_root`. It adds no TLS implementation, environment lookup, native-store inspection, parser emulation or new bounded context.

Exact-head GREEN is not claimed here. It requires a successor exact head containing this repair, this test and this doctoring to pass the then-live hosted formatting, locked workspace tests, strict Clippy, Fuzz, security/static-analysis, review and thread gates. Predecessor results do not transfer after head movement.

## Security properties and limits

- The reviewed uv install remains admissible when no native-store selector is present.
- Structured `uv ... --system-certs` fails closed with the stable `alternate_trust_root` reason.
- The classifier is uv-specific rather than a global spelling blacklist.
- Ambient `UV_SYSTEM_CERTS`, project/user configuration and the actual native store are outside this structured-argv contract and remain runtime/configuration concerns for the canonical quarantine boundary.
- Wardnet does not assert that a native store is malicious or invalid. It asserts that changing the reviewed trust-authority source requires separate authorization.
- The admission receipt is not proof of certificate validation, retrieved artifact bytes, isolation or egress enforcement.

## Traceability

Astral Software, Inc. (n.d.). *Commands: uv pip install — --system-certs*. uv. Retrieved September 11, 2026, from https://docs.astral.sh/uv/reference/cli/

Astral Software, Inc. (n.d.). *Settings*. uv. Retrieved September 11, 2026, from https://docs.astral.sh/uv/reference/settings/

National Institute of Standards and Technology. (2025). *Security and privacy controls for information systems and organizations, Release 5.2.0* (NIST SP 800-53 Rev. 5). CM-6 requires security-relevant configuration settings to be established, implemented, and controlled; SC-17 addresses public-key-infrastructure certificates. Release 5.2.0 was finalized August 27, 2025. https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final

National Institute of Standards and Technology. (2026, July 24). *Security configuration settings*. Risk Management Framework. https://csrc.nist.gov/Projects/risk-management/about-rmf/implement-step/security-configuration-settings

MITRE. (2026, April 30). *CWE-15: External control of system or configuration setting* (CWE 4.20). https://cwe.mitre.org/data/definitions/15.html

MITRE. (2026, April 30). *CWE-295: Improper certificate validation* (CWE 4.20). https://cwe.mitre.org/data/definitions/295.html

## Follow-up

Reacquire exact-head hosted GREEN after this doctoring commit. Then verify current reviews/threads and exact #129 base compatibility before ordinary expected-head integration of #289 into #129. Reacquire canonical #129 gates on its new exact head before opening serialized #286; #288 remains behind #286. Keep #285 open until the effective delta reaches protected `main` or is fully inherited by a verified successor.
