# uv configuration authority

## Problem and security boundary

Wardnet Agent Artifact Admission binds an approved PyPI request to reviewed package coordinates, registry/index identity, digest, dependency cardinality and selected installer safety controls before any executor runs. `uv` also accepts the global `--config-file <path>` selector, which selects a caller-supplied `uv.toml`. Astral documents both this CLI selector and configuration-file index settings, including a default package index. If an untrusted agent can select that file, the same structured install intent can delegate package-source and trust configuration to data outside the reviewed admission coordinate.

The selector is security-significant independently of whether Wardnet's narrower executable grammar supports that exact global-option placement. An unsupported command must remain fail-closed, but its evidence should still retain the causal configuration-authority reason rather than degrading to only a generic forbidden-command reason.

This is Wardnet policy authority, not transport execution. Wardnet therefore rejects the caller-selected configuration selector wherever its exact documented argv spelling is observable. EgressWeave remains the canonical executable outbound URL/address/DNS/peer/redirect/proxy/TLS authorization owner, while `quarantine-sandbox-runtime` remains the effective runtime environment/filesystem/process isolation owner.

## Constraints and alternatives

The repair must preserve the existing direct `uv pip install` capability, existing exact `name==version` artifact-source identity, `--require-hashes`, `--no-deps`, and explicit index/TLS override controls. It must not widen Wardnet's supported uv execution grammar, parse or trust the selected `uv.toml`, copy uv configuration semantics into Wardnet, infer ambient `UV_CONFIG_FILE`, or infer that an EgressWeave transport allow would authorize a different package source.

Three alternatives were considered:

1. Parse the selected configuration file and admit a request when its effective index appears equivalent. Rejected because this creates a second uv configuration interpreter inside Wardnet and moves runtime/configuration truth into the wrong bounded context.
2. Rely on EgressWeave to block the resulting network destination. Rejected because transport authorization cannot repair a pre-execution admission decision whose reviewed package authority has already been widened.
3. Classify exact `--config-file` and `--config-file=<path>` as alternate trust/configuration authority anywhere in the observed uv argv while leaving executable support validation separate. Chosen because it is fail-closed, minimal, reversible, preserves causal evidence for documented global placement, and does not broaden what Wardnet is willing to execute.

## RED and causal repair

Issue #264 records the original hostile case. Test-only commit `a718e68bd7f13df9d54f5bd85ef7cde781d4827d`, stacked directly on canonical Agent Artifact Admission #129, added an otherwise-approved uv install plus attached and separate configuration-file selectors after `uv pip install`. Hosted CI run `34490519712`, rust job `102915749368`, passed checkout, Rust setup and formatting, then failed in the test phase. The causal repair in #265 introduced the Wardnet-local configuration-authority classifier for that supported command placement.

Successor review on canonical `#129@3f89f56c2de9039e9e6a9e34e4c6686f0eaf6da2` then found a placement-specific evidence defect: because the classifier first required fixed-position `uv pip install`, documented global forms such as `uv --config-file /tmp/attacker-uv.toml pip install ...` remained blocked only by the generic command grammar and did not carry `alternate_trust_root`.

Successor test-only exact `b69312002943ff419152dd58dbc1880649120e44` added hermetic separate-value and attached-value global forms plus a near-spelling negative semantic control while production source remained byte-identical. Hosted CI `34715293235`, rust job `103611334897`, passed checkout, toolchain and formatting and then failed in the Test step; Clippy was skipped. That is the causal RED for missing security evidence rather than runner/bootstrap noise.

The minimum successor repair recognizes exact `--config-file` and `--config-file=...` together with the already-bound global `--directory` selector before fixed subcommand-position validation. It leaves `supported_install_command` unchanged, so an otherwise unsupported global-option command remains generically forbidden in addition to carrying the causal `alternate_trust_root` reason. `--torch-backend` remains scoped to the currently supported fixed-position `uv pip install` grammar. No ambient configuration is inferred and no selected file is read.

## Risk and follow-up

The CLI selector is only one configuration channel. Environment-provided configuration such as `UV_CONFIG_FILE`, inherited user/system files, and effective runtime filesystem visibility cannot be proven from the structured argv alone and remain downstream runtime/configuration authority. Agent Artifact Admission must continue to fail closed on caller-controlled argv channels it can observe without claiming control over ambient execution state.

A child merge into #129 is not protected-product completion. #264 remains open until the integrated Agent Artifact Admission lineage reaches protected `main`, and each successor #129 head must reacquire exact-head CI, fuzz, security, SAST and delegated CodeQL evidence without predecessor transfer.

## Traceability

- CWE-15 describes the weakness class in which externally controlled input changes system or configuration settings that affect behavior. The uv configuration selector is treated here as an admission authority change rather than ordinary argument detail.
- NIST SSDF PW.4 requires reusable security controls and secure coding practices to prevent common vulnerabilities; the fail-closed classifier is a narrow preventive control at the command-admission boundary.
- Astral's uv CLI reference is authoritative for the global `--config-file` selector; Astral's configuration-file documentation is authoritative for configuration-defined package indexes.

## References

Astral Software, Inc. (2026). *uv command-line reference*. https://docs.astral.sh/uv/reference/cli/

Astral Software, Inc. (2026). *Configuration files*. https://docs.astral.sh/uv/configuration/files/

MITRE. (2026). *CWE-15: External control of system or configuration setting*. https://cwe.mitre.org/data/definitions/15.html

National Institute of Standards and Technology. (2022). *Secure software development framework (SSDF) version 1.1: Recommendations for mitigating the risk of software vulnerabilities (NIST SP 800-218).* https://doi.org/10.6028/NIST.SP.800-218
