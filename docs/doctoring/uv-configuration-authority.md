# uv configuration authority

## Problem and security boundary

Wardnet Agent Artifact Admission binds an approved PyPI request to reviewed package coordinates, registry/index identity, digest, dependency cardinality and selected installer safety controls before any executor runs. `uv` also accepts command-line and configuration selectors that can change where packages are fetched from. Astral documents the top-level grammar as `uv [OPTIONS] <COMMAND>`, so reviewed global options can precede the active subcommand, and documents `--torch-backend` as a `uv pip` source selector for PyTorch-ecosystem packages.

Two observable authority changes are security-significant here. First, global `--config-file <path>` can select caller-supplied configuration containing package-index settings. Second, `--torch-backend` causes uv to ignore configured index URLs for PyTorch-ecosystem packages and use the selected backend/index instead. An approved package coordinate must therefore not inherit admission merely because either selector appears in a syntactically different, but documented, parser phase.

The selectors are security-significant independently of whether Wardnet's narrower executable grammar supports every documented global-option placement. An unsupported command must remain fail-closed, but its evidence should retain the causal configuration/source-authority reason rather than degrading to only a generic forbidden-command reason.

This is Wardnet policy and security-evidence authority, not transport execution. Wardnet therefore classifies caller-selected configuration/source authority where the exact documented argv spelling is observable. EgressWeave remains the canonical executable outbound URL/address/DNS/peer/redirect/proxy/TLS authorization owner, while `quarantine-sandbox-runtime` remains the effective runtime environment/filesystem/process isolation owner.

## Constraints and alternatives

The repair must preserve the existing direct `uv pip install` capability, existing exact `name==version` artifact-source identity, `--require-hashes`, `--no-deps`, and explicit index/TLS override controls. It must not widen Wardnet's supported uv execution grammar, parse or trust a selected `uv.toml`, copy uv configuration semantics into Wardnet, infer ambient `UV_CONFIG_FILE` or `UV_TORCH_BACKEND`, or infer that an EgressWeave transport allow would authorize a different package source.

Three alternatives were considered:

1. Parse selected configuration and admit a request when its effective index appears equivalent. Rejected because this creates a second uv configuration interpreter inside Wardnet and moves runtime/configuration truth into the wrong bounded context.
2. Rely on EgressWeave to block the resulting network destination. Rejected because transport authorization cannot repair a pre-execution admission decision whose reviewed package authority has already been widened.
3. Use the existing bounded `uv_active_command_index` parser to separate reviewed uv global options from the active command, then classify only exact source-authority selectors in their owned parser slice while leaving executable support validation separate. Chosen because it is fail-closed, minimal, reversible, preserves causal evidence for documented placement, and does not broaden what Wardnet is willing to execute.

## RED and causal repair

Issue #264 records the original `--config-file` hostile case. Test-only commit `a718e68bd7f13df9d54f5bd85ef7cde781d4827d`, stacked directly on canonical Agent Artifact Admission #129, added an otherwise-approved uv install plus attached and separate configuration-file selectors after `uv pip install`. Hosted CI run `34490519712`, rust job `102915749368`, passed checkout, Rust setup and formatting, then failed in the test phase. The causal repair in #265 introduced the Wardnet-local configuration-authority classifier for that supported command placement.

Successor review on canonical `#129@3f89f56c2de9039e9e6a9e34e4c6686f0eaf6da2` then found a placement-specific evidence defect: because the classifier first required fixed-position `uv pip install`, documented global forms such as `uv --config-file /tmp/attacker-uv.toml pip install ...` remained blocked only by the generic command grammar and did not carry `alternate_trust_root`.

Successor test-only exact `b69312002943ff419152dd58dbc1880649120e44` added hermetic separate-value and attached-value global forms plus a near-spelling negative semantic control while production source remained byte-identical. Hosted CI `34715293235`, rust job `103611334897`, passed checkout, toolchain and formatting and then failed in the Test step; Clippy was skipped. That is the causal RED for missing security evidence rather than runner/bootstrap noise. The minimum successor repair recognizes exact `--config-file` and `--config-file=...` together with the already-bound global `--directory` selector before supported-command validation.

Issue #389 records the next source-authority evidence defect. The configuration classifier already reused `uv_active_command_index`, but `--torch-backend` attribution still assumed fixed-position `uv pip install`. A documented global option could therefore shift the active `pip` command and hide the causal `alternate_trust_root` reason. Formatting-only test head `68835aca70757f9e17ae53c8f37d7729a2ff1cc5` kept production source byte-identical to its exact #129 parent and added both `uv --color never pip install ... --torch-backend=cpu` and separate-value `--torch-backend cpu` cases. Hosted CI `34729809606`, rust job `103650392270`, passed checkout, toolchain and formatting and then failed in the Test step, establishing the semantic RED.

The minimum #390 repair reuses the existing `uv_active_command_index`; it does not create another uv parser. After locating the active top-level command it requires exact `pip` followed by exact `install`, and scans only that pip-install argument slice for exact `--torch-backend` or `--torch-backend=...`. Delegated `uv run` child argv is not interpreted as uv package-source authority. `supported_install_command` remains unchanged, so an otherwise unsupported global-option command remains generically forbidden in addition to carrying the causal `alternate_trust_root` reason. Exact submitted argv identity remains part of admission evidence.

## Risk and follow-up

The CLI selectors are only observable configuration channels. Environment-provided configuration such as `UV_CONFIG_FILE` and `UV_TORCH_BACKEND`, inherited user/system files, and effective runtime filesystem visibility cannot be proven from the structured argv alone and remain downstream runtime/configuration authority. Agent Artifact Admission must continue to fail closed on caller-controlled argv channels it can observe without claiming control over ambient execution state.

Astral marks `torch-backend` as preview behavior that may change. The parser therefore deliberately binds only the documented exact option spelling and `uv pip install` source-authority slice rather than copying backend/index tables or broader uv semantics into Wardnet. Future uv changes require a fresh hostile contract and exact-head evidence before policy expansion.

A child merge into #129 is not protected-product completion. #264 and #389 remain open until their effective Agent Artifact Admission lineage reaches protected `main` or a verified complete successor, and each successor #129 head must reacquire exact-head CI, fuzz, security, SAST and delegated CodeQL evidence without predecessor transfer.

## Traceability

- CWE-15 describes the weakness class in which externally controlled input changes system or configuration settings that affect behavior. The uv configuration and package-source selectors are treated here as admission authority changes rather than ordinary argument detail.
- NIST SSDF PW.4 directs software producers to reuse existing, well-secured software when feasible instead of duplicating functionality, with particular importance for security functionality. Reusing Wardnet's already-reviewed bounded `uv_active_command_index` parser rather than adding a second uv parser aligns with that practice and reduces divergent security interpretation. The repository already carries the redistributable NIST SP 800-218 source PDF under `docs/papers/`; no duplicate copy is needed for this change.
- Astral's current CLI reference is authoritative for the top-level `uv [OPTIONS] <COMMAND>` grammar and global `--color` option. This is why evidence classification cannot assume that `pip` is always the first token after the executable.
- Astral's settings reference states that `torch-backend` changes package fetching for the PyTorch ecosystem, ignores configured index URLs for those packages, and is respected only by `uv pip` commands. This establishes `--torch-backend` as package-source authority rather than a presentation or performance flag.
- Astral's PyTorch integration guide documents current command-line forms such as `uv pip install torch --torch-backend=auto` and specific backend selection. These vendor pages are linked rather than copied into `docs/papers/`: this change does not assert a redistribution license for snapshots of the Astral documentation.

## References

Astral Software, Inc. (2026). *uv command-line reference*. https://docs.astral.sh/uv/reference/cli/

Astral Software, Inc. (2026). *uv settings reference*. https://docs.astral.sh/uv/reference/settings/

Astral Software, Inc. (2026, August 14). *Using uv with PyTorch*. https://docs.astral.sh/uv/guides/integration/pytorch/

Astral Software, Inc. (2026). *Configuration files*. https://docs.astral.sh/uv/configuration/files/

MITRE. (2026). *CWE-15: External control of system or configuration setting*. https://cwe.mitre.org/data/definitions/15.html

Souppaya, M., Scarfone, K., & Dodson, D. (2022). *Secure software development framework (SSDF) version 1.1: Recommendations for mitigating the risk of software vulnerabilities (NIST SP 800-218).* National Institute of Standards and Technology. https://doi.org/10.6028/NIST.SP.800-218
