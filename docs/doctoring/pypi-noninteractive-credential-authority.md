# PyPI noninteractive credential authority

Verified 2026-09-11. This note documents why Wardnet Agent Artifact Admission requires direct `pip` and `pip3 install` intents to include the canonical `--no-input` token before an allow decision can be returned.

## Problem and security boundary

An exact package name, version, registry, owner assertion, digest, reviewed manifest and `--require-hashes` do not by themselves bound credential discovery. pip's authentication layer can consult ambient credential mechanisms independently of artifact identity. Wardnet owns only the pre-execution admission verdict and evidence for the submitted installer intent; it does not obtain credentials, perform package-network I/O, install artifacts, or execute them. Keyverse remains the credential/identity backend, EgressWeave remains reusable outbound-transport authority, and `quarantine-sandbox-runtime` remains hostile execution/isolation authority.

## Primary evidence

The pip 26.2.1 authentication documentation states that the default keyring provider is `auto`; when `--no-input` is present, `auto` does not query keyring, while without that option it may try the import and subprocess providers before falling back to disabled. The same documentation warns that keyring backends can require user interaction. In the pinned upstream source used for this decision (`pypa/pip@2b28a816d043826f2ba10ff1d22ec3d94d2ed7c5`, `src/pip/_internal/network/auth.py`), `MultiDomainBasicAuth.use_keyring` is true whenever prompting remains enabled, and the `auto` provider can first import ambient Python `keyring` and then discover a `keyring` executable through `PATH`.

Therefore an otherwise reviewed direct pip intent that omits `--no-input` retains ambient/interactively mediated credential authority not represented by `ApprovedArtifact` or the reviewed workspace manifest. Wardnet fails that intent closed rather than attempting to emulate pip's complete authentication state machine.

## Decision

For direct `pip install` and `pip3 install` only:

- the exact token `--no-input` is mandatory;
- omission yields the existing stable `missing_safety_flag` reason and a block decision;
- look-alike or assigned forms do not satisfy the guard;
- explicit credential-provider expansion remains separately governed by `pypi_keyring_provider_authority`;
- uv is not silently included in this rule because its CLI/authentication contract is versioned and reviewed separately.

This is intentionally a minimum causal control. It does not claim that `--no-input` proves retrieved artifact bytes, credential provenance, transport authorization, or runtime isolation. Those remain independently verified owner responsibilities.

## Executable evidence

`tests/pypi_noninteractive_authority_contract.rs` proves both hostile and positive cases for `pip` and `pip3`: an otherwise approved direct install without `--no-input` blocks with `missing_safety_flag`, while the same exact reviewed intent with canonical `--no-input` remains admissible. Positive direct-pip fixtures in the existing PyPI authority suite carry the same invariant so a future policy change cannot accidentally preserve stale permissive baselines.

The test-first lineage is recorded on Wardnet PR #283: test-only RED `124e1eb2cce935d83d302b265633a6d6c62482cf`, followed by the focused classifier and fixture-adoption repairs. Remote workflow results are valid only for the exact current PR head; predecessor runs are historical evidence after any source or documentation movement.

## Alternatives considered

Allowing pip's default interactive behavior was rejected because the decision would authorize credential-discovery capability absent from the reviewed intent. Reproducing pip's keyring/configuration precedence inside Wardnet was rejected because it would create a second package-client authentication authority and would drift as pip evolves. Forcing a particular credential backend was rejected because credential selection belongs outside this admission bounded context.

## Risks and follow-up

`--no-input` narrows one ambient credential path but does not neutralize every pip configuration or environment-controlled trust expansion. Each independently demonstrated authority expansion should receive its own hostile RED and minimum classifier rather than broad parser imitation. In particular, uv credential-provider and certificate-store controls are tracked separately so direct-pip semantics are not generalized across executable families without primary evidence.

## APA 7 references

Booth, H., Souppaya, M., Vassilev, A., Ogata, M., Stanley, M., & Scarfone, K. (2024). *Secure software development practices for generative AI and dual-use foundation models: An SSDF community profile (NIST SP 800-218A).* National Institute of Standards and Technology. https://doi.org/10.6028/NIST.SP.800-218A

pip developers. (2026). *Authentication: pip documentation v26.2.1.* https://pip.pypa.io/en/stable/topics/authentication/

pip developers. (2026). *Network authentication helpers* [Source code, commit 2b28a816d043826f2ba10ff1d22ec3d94d2ed7c5]. GitHub. https://github.com/pypa/pip/blob/2b28a816d043826f2ba10ff1d22ec3d94d2ed7c5/src/pip/_internal/network/auth.py
