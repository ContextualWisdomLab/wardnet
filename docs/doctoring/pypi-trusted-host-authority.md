# Direct pip trusted-host abbreviation authority

## Problem and boundary

Wardnet's Agent Artifact Admission is a pre-execution policy and evidence boundary. It must reject caller-selected package trust authority that is not represented by the reviewed artifact policy. It does not perform TLS, package retrieval, egress authorization, installation, isolation, or activation; those remain with their canonical runtime/transport owners.

Direct `pip`/`pip3` uses Python's optparse-compatible long-option grammar. The canonical `--trusted-host` option is already denied by Wardnet's generic exact trust-root guard, but the parser also accepts unambiguous prefixes. A hostile otherwise-approved intent using attached `--tr=attacker.invalid` therefore exercised the same pip trust control without matching the exact Wardnet flag.

## Exact RED evidence

Test-only commit `40eab9ac1e919fb4411a7d05f574371ed7b80a29`, based on exact #129 head `25366eb291b783cd211bb76b8eadd8e853d722d1`, added `pypi_trusted_host_authority_contract.rs` and no production change. Hosted CI run `34630752242`, job `103366710451`, completed checkout and formatting successfully and then failed in `cargo test --locked --workspace`. The parent head had terminal GREEN CI, so the isolated hostile contract is the causal delta.

The executable pip parser independently accepts `--tr=attacker.invalid`; `--t=attacker.invalid` remains ambiguous because it can prefix other pip options. Wardnet therefore must not guess shorter prefixes.

## Decision

Extend only Wardnet's direct-pip registry/source trust classifier. For `pip` and `pip3` direct install intents, classify verified prefixes from `--tr` through the character before the full `--trusted-host` spelling as `AlternateTrustRoot`. Leave the canonical full spelling under the existing generic exact-option guard. Keep uv and other package managers out of this parser-specific overlay.

Rejected alternatives:

- Blocking every `--t*` token would invent parser behavior and reject valid or ambiguous pip options without evidence.
- Implementing TLS validation or outbound transport enforcement in Wardnet would duplicate EgressWeave/runtime ownership.
- Treating any option prefix as equivalent across installers would violate each tool's actual command grammar.

## Security effect and residual risk

The repair closes an admission-evidence bypass in which a caller could select pip's trusted-host policy while inheriting an approved artifact decision. It does not claim that Wardnet validates server certificates or enforces network transport. Future pip parser changes remain a compatibility risk; parser-significant options require RED contracts before expanding the accepted/forbidden grammar.

## Traceability

- NIST SSDF: verify software requirements and design against security requirements, then use executable tests to prevent recurrence of a discovered weakness.
- CWE-295: weakening or bypassing certificate/peer validation can permit an attacker-controlled endpoint to be trusted.
- Python `optparse`: long options may be abbreviated when the supplied prefix is unambiguous.
- pip: `--trusted-host <hostname>` explicitly marks a host trusted even when it does not have valid or any HTTPS.

## References (APA 7th)

National Institute of Standards and Technology. (2022). *Secure software development framework (SSDF) version 1.1: Recommendations for mitigating the risk of software vulnerabilities* (NIST Special Publication 800-218). https://doi.org/10.6028/NIST.SP.800-218

Python Packaging Authority. (n.d.). *pip install*. pip documentation. Retrieved September 12, 2026, from https://pip.pypa.io/en/stable/cli/pip_install/

Python Packaging Authority. (n.d.). *General options*. pip documentation. Retrieved September 12, 2026, from https://pip.pypa.io/en/stable/cli/pip/

Python Software Foundation. (n.d.). *optparse — Parser for command line options*. Python documentation. Retrieved September 12, 2026, from https://docs.python.org/3/library/optparse.html

MITRE. (n.d.). *CWE-295: Improper certificate validation*. Common Weakness Enumeration. Retrieved September 12, 2026, from https://cwe.mitre.org/data/definitions/295.html
