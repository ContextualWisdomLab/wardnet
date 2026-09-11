# uv keyring provider credential authority

Status: Proposed implementation evidence on Draft #287. This note is not protected or released truth until the effective delta reaches protected `main`.

## Decision

Wardnet treats caller-selected `uv pip install --keyring-provider <value>` as an expansion of credential/trust authority unless the value is exactly `disabled`. The decision blocks before execution with the existing stable `alternate_trust_root` reason. Ordinary uv behavior remains admissible, and explicitly retaining `--keyring-provider=disabled` does not expand authority.

Astral currently documents only `disabled` and `subprocess`, with keyring authentication disabled by default. Denying other explicit values is a forward-compatible admission rule, not a claim that today's uv parser accepts those values. Wardnet does not bind the installed uv binary/version in this intent; therefore an explicit unknown value cannot be safely treated as permanently inert if a later client release adds a new active credential provider.

This decision is deliberately limited to Wardnet's structured installer-intent admission boundary. Wardnet does not execute `keyring`, inspect `PATH`, read credentials, select runtime environment configuration, or authorize network transport. Keyverse remains the credential/identity backend; `quarantine-sandbox-runtime` remains effective runtime/environment and hostile-execution authority; EgressWeave remains executable outbound transport/TLS authority.

## Problem and threat model

Astral's current uv documentation states that keyring authentication is disabled by default and that uv currently supports only the `subprocess` provider. The subprocess provider invokes the `keyring` command to obtain credentials. Consequently, a caller can keep the reviewed package name/version/registry/hash and dependency cardinality unchanged while adding a new PATH-resolved credential-helper execution dependency through argv.

The first repair blocked the currently active `subprocess` literal. Fresh review identified a second-order fail-open: because the Wardnet intent does not attest the uv client version, a future uv release could add another non-disabled provider. An argv value rejected today could then begin discovering credentials under an already-approved Wardnet policy unless the admission contract treats every explicit non-disabled provider as authority-bearing.

For Agent Artifact Admission, that is a material authority change. The reviewed artifact coordinate does not authorize the identity, behavior or credential sources of ambient helper executables, and admission receipts must not silently gain meaning after client capability evolution.

## Alternatives considered

### Allow uv's provider selector and delegate all enforcement downstream

Rejected. Quarantine and EgressWeave own runtime isolation and transport, but Wardnet still owns whether the structured install intent is admissible. Deferring an argv-visible authority expansion would make admission receipts overstate what was reviewed.

### Resolve and attest the `keyring` executable inside Wardnet

Rejected. PATH resolution, process execution and effective environment inspection belong to the runtime boundary, not the admission policy evaluator. Pulling those capabilities into Wardnet would duplicate quarantine/Keyverse responsibilities and make a deterministic policy decision depend on ambient state.

### Block only today's `subprocess` provider

Rejected after hostile review. It is sufficient only while upstream's provider set is frozen. Wardnet does not bind that client capability version, so the rule would fail open if another active provider were introduced later.

### Block every explicit provider including `disabled`

Rejected. uv's default is disabled, and explicitly retaining `disabled` adds no credential-helper authority. The narrower invariant is therefore “every explicit non-disabled provider is authority-expanding.”

### Reuse pip-compatible option abbreviation matching for uv

Rejected. The existing direct-pip classifier intentionally recognizes pinned pip parser abbreviations. uv's CLI is a different grammar. Wardnet matches the exact uv option name rather than assuming pip abbreviation behavior.

## RED → repair evidence

Canonical parent #129 is `341a3e05a614654536431eda8e553585b2533886`.

Initial test-only #287 head `85b7b55648f29dc45a38dd01134583610fb0952f` changed only `crates/agent-artifact-admission/tests/uv_keyring_provider_authority_contract.rs`; production source remained byte-identical to the parent. Parent CI `34542090175` is terminal success. Child CI `34542208606`, rust job `103087106839`, acquired hosted `ubuntu-24.04`, passed checkout/toolchain/format, then failed in Test because attached `--keyring-provider=subprocess` remained `Allow`. Fuzz `34542208653` is terminal success. This is hosted semantic RED for the original subprocess authority gap.

Minimum production repair `9ce55e3f999932a041610bb7e67e47f406a4e9a6` extended the existing PyPI keyring-provider classifier to the admitted `uv pip install` command path while preserving direct pip/pip3 abbreviation and `import|subprocess` behavior. Follow-up `fca4c79151c1ae88cf36414e97d63ffd6ac4d0ca` added attached/separate subprocess reason coverage and explicit `disabled` preservation.

Fresh review then added the future-provider hostile contract in test-only `7121333b2f37eb6a721e730c9c91a1f29dff63c1`: an explicit unknown non-disabled value must fail closed while exact `disabled` remains admissible. Formatter-only successors preserved production semantics until exact `7f7582fa06db5108de6e22aa33eb9e9470fec815` reached hosted CI `34547136579`, rust job `103102105097`, runner `1001873718`. Formatting succeeded; the locked workspace Test step ran. Every preceding suite shown in the job log passed, including the existing direct-pip keyring contract and the three other uv keyring tests. `unknown_non_disabled_uv_keyring_provider_fails_closed` alone failed with `left: Allow`, `right: Block`; Clippy was skipped because Test failed. This is the required hosted semantic RED for forward-compatible provider authority.

Minimum causal repair `3e8725c87e61e8a667573704b6478f76c503af1e` changes only the existing classifier predicate: direct pip/pip3 still blocks the same known `import|subprocess` providers, exact uv `--keyring-provider` now treats every value except `disabled` as authority-expanding. It adds no uv parser emulation, PATH lookup, credential access, environment inspection, transport behavior or new bounded context.

Exact-head GREEN is not claimed here. It requires a successor exact head containing this repair and this doctoring to pass hosted formatting, locked workspace tests, strict Clippy, Fuzz and the then-live security/static-analysis/review/thread gates. Predecessor results do not transfer after head movement.

## Security properties and limits

- Admission fails closed for any argv-visible non-disabled uv provider, including future provider values not supported by the current client.
- Exact `disabled` remains the sole explicit no-provider baseline.
- Direct pip/pip3 keyring semantics and pinned abbreviation behavior are unchanged.
- The decision uses the existing `alternate_trust_root` reason rather than inventing a parallel credential taxonomy.
- Wardnet performs no helper discovery or credential access.
- Environment/config forms such as `UV_KEYRING_PROVIDER` remain effective runtime/configuration authority and must be constrained by the canonical runtime boundary; Wardnet does not claim to observe them from this structured argv contract.
- The admission receipt remains evidence of pre-execution policy only, not proof of retrieved bytes, runtime isolation, transport authorization or activation.

## Traceability

Astral Software, Inc. (2026). *Compatibility with pip: Registry authentication*. uv. https://docs.astral.sh/uv/pip/compatibility/

Astral Software, Inc. (2026). *HTTP credentials*. uv. https://docs.astral.sh/uv/concepts/authentication/http/

National Institute of Standards and Technology. (2024). *Secure software development practices for generative AI and dual-use foundation models: An SSDF community profile* (NIST SP 800-218A). https://doi.org/10.6028/NIST.SP.800-218A

National Institute of Standards and Technology. (2025). *Security and privacy controls for information systems and organizations, Release 5.2.0* (NIST SP 800-53 Rev. 5). Relevant least-privilege and authenticator-management controls include AC-6 and IA-5. https://csrc.nist.gov/projects/risk-management/sp800-53-controls

MITRE. (2025). *CWE-15: External control of system or configuration setting*. https://cwe.mitre.org/data/definitions/15.html

## Follow-up

Reacquire exact-head hosted GREEN after this repair and doctoring. Then verify current reviews/threads and exact #129 base compatibility before ordinary expected-head integration of #287 into #129. Reacquire canonical #129 gates on its new exact head before starting serialized #285; #286 and #288 follow. Keep #284 open until the effective delta reaches protected `main`.