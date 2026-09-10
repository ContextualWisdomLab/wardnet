# uv subprocess keyring credential authority

Status: Proposed implementation evidence on Draft #287. This note is not protected or released truth until the effective delta reaches protected `main`.

## Decision

Wardnet treats caller-selected `uv pip install --keyring-provider subprocess` as an expansion of credential/trust authority and blocks it before execution with the existing stable `alternate_trust_root` reason. The ordinary uv baseline remains admissible, and explicit `--keyring-provider=disabled` does not expand authority.

This decision is deliberately limited to Wardnet's structured installer-intent admission boundary. Wardnet does not execute `keyring`, inspect `PATH`, read credentials, select runtime environment configuration, or authorize network transport. Keyverse remains the credential/identity backend; `quarantine-sandbox-runtime` remains effective runtime/environment and hostile-execution authority; EgressWeave remains executable outbound transport/TLS authority.

## Problem and threat model

Astral's current uv documentation states that keyring authentication is disabled by default and that uv supports only the `subprocess` keyring provider. The subprocess provider invokes the `keyring` command to obtain credentials. Consequently, a caller can keep the reviewed package name/version/registry/hash and dependency cardinality unchanged while adding a new PATH-resolved credential-helper execution dependency through argv.

For Agent Artifact Admission, that is a material authority change: the reviewed artifact coordinate does not itself authorize the identity, behavior or credential sources of an ambient helper executable. Allowing the selector would let execution-time environment state decide part of authentication outside the reviewed installer intent.

## Alternatives considered

### Allow uv's provider selector and delegate all enforcement downstream

Rejected. Quarantine and EgressWeave own runtime isolation and transport, but Wardnet still owns whether the structured install intent is admissible. Deferring an argv-visible authority expansion would make admission receipts overstate what was reviewed.

### Resolve and attest the `keyring` executable inside Wardnet

Rejected. PATH resolution, process execution and effective environment inspection belong to the runtime boundary, not the admission policy evaluator. Pulling those capabilities into Wardnet would duplicate quarantine/Keyverse responsibilities and make a deterministic policy decision depend on ambient state.

### Block all `--keyring-provider` values

Rejected. uv's default is disabled, and explicitly retaining `disabled` adds no credential-helper authority. A value-sensitive classifier is narrower and preserves a safe reviewed baseline.

### Reuse pip-compatible option abbreviation matching for uv

Rejected. The existing direct-pip classifier intentionally recognizes pinned pip parser abbreviations. uv's CLI is a different grammar. Wardnet matches the exact uv option name rather than assuming pip abbreviation behavior.

## RED → GREEN evidence

Canonical parent #129 is `341a3e05a614654536431eda8e553585b2533886`.

Test-only #287 head `85b7b55648f29dc45a38dd01134583610fb0952f` changed only `crates/agent-artifact-admission/tests/uv_keyring_provider_authority_contract.rs`; production source remained byte-identical to the parent. Parent CI `34542090175` is terminal success. Child CI `34542208606`, rust job `103087106839`, later acquired hosted `ubuntu-24.04` runner `1001872102`, passed checkout/toolchain/format, then failed in the Test step. Because the only child delta was the new admission contract and the exact parent suite was green, this is the required hosted semantic RED for the uv subprocess-keyring authority gap; Fuzz `34542208653` is terminal success on the test-only head.

The minimum production repair commit `9ce55e3f999932a041610bb7e67e47f406a4e9a6` extends the existing PyPI keyring-provider authority classifier to the admitted `uv pip install` command path. It preserves direct pip/pip3 abbreviation and `import|subprocess` behavior, but uv matches only the exact `--keyring-provider` option and treats only `subprocess` as authority-expanding. Follow-up test commit `fca4c79151c1ae88cf36414e97d63ffd6ac4d0ca` covers attached subprocess, separate-value subprocess reason classification and explicit attached `disabled` preservation.

Exact-head GREEN must be recorded only after the current `fca4c791...` (or a later causally necessary head) passes hosted formatting, locked workspace tests, strict Clippy, Fuzz and the then-live security/static-analysis gates. Predecessor results do not transfer after head movement.

## Security properties and limits

- Admission is fail-closed for the argv-visible subprocess provider.
- The decision uses the existing `alternate_trust_root` reason rather than inventing a parallel credential taxonomy.
- Wardnet performs no helper discovery or credential access.
- Environment/config forms such as `UV_KEYRING_PROVIDER` remain effective runtime/configuration authority and must be constrained by the canonical runtime boundary; Wardnet does not claim to observe them from this structured argv contract.
- The admission receipt remains evidence of pre-execution policy only, not proof of retrieved bytes, runtime isolation, transport authorization or activation.

## Traceability

Astral. (2026). *Compatibility with pip: Registry authentication*. uv. https://docs.astral.sh/uv/pip/compatibility/

Astral. (2025). *HTTP credentials*. uv. https://docs.astral.sh/uv/concepts/authentication/http/

National Institute of Standards and Technology. (2024). *Secure software development practices for generative AI and dual-use foundation models: An SSDF community profile* (NIST SP 800-218A). https://doi.org/10.6028/NIST.SP.800-218A

National Institute of Standards and Technology. (2025). *Security and privacy controls for information systems and organizations, Release 5.2.0* (NIST SP 800-53 Rev. 5). Relevant least-privilege and authenticator-management controls include AC-6 and IA-5. https://csrc.nist.gov/projects/risk-management/sp800-53-controls

MITRE. (2025). *CWE-15: External control of system or configuration setting*. https://cwe.mitre.org/data/definitions/15.html

## Follow-up

After exact hosted GREEN, verify current reviews/threads and base compatibility, then integrate #287 into #129 by ordinary expected-head merge. Reacquire the canonical #129 gates on its new exact head before starting the serialized #285/#286 source lanes. Keep #284 open until the effective delta reaches protected `main`.