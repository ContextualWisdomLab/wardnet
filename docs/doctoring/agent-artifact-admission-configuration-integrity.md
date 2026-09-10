# Agent Artifact Admission configuration-file integrity

## Decision under review

Wardnet treats the Agent Artifact Admission configuration as policy authority, not as a secret. The file contains the reviewed policy revision, executable allowlist, workspace-manifest digests, and exact artifact coordinates. Read-only group or other visibility therefore does not change admission authority, but group or other write authority does: an unintended writer could replace an approved digest, artifact coordinate, or executable and thereby alter the result of a later admission decision.

On Unix, the loader opens the configured path once and inspects permissions through metadata obtained from that already-open `File` before reading and parsing its bytes. It rejects any group/other write bit (`mode & 0o022 != 0`) as `ConfigError::InvalidConfiguration`. This intentionally permits read-only modes such as `0644` while rejecting policy-mutation authority such as `0664` or `0666`. The separate credential loader remains stricter because credential confidentiality, unlike policy-file confidentiality, is itself a security requirement.

The same-open-handle sequence is deliberate. A path-level permission check followed by a separate open would create a check/use interval in which the pathname could resolve to a different object. Dean and Hu (2004) formalize this class of filesystem TOCTOU race and show why a security decision separated from acquisition is unsafe under an adversarial pathname. Borisov et al. (2005) subsequently demonstrate that probabilistic attempts to make such path races difficult remain exploitable, reinforcing the preference for descriptor-bound checks rather than repeated pathname checks. Wardnet does not claim that descriptor metadata alone solves every filesystem replacement problem; it closes the narrower defect in this slice: deciding whether the bytes already opened as policy are writable by unintended Unix principals before those same opened bytes are materialized.

On non-Unix targets, this version fails closed because the product has not defined or tested a native ACL-equivalence contract for policy mutation authority. Silently accepting the configuration would assert a security property the implementation cannot currently verify. Adding Windows ACL or another platform-native authority model is a separate compatibility increment and must retain the same fail-closed invariant.

## Executable acceptance contract

`config_file_permissions_contract.rs` creates one valid configuration, applies safe and unsafe Unix modes to the same fixture, and calls the public loader. Safe modes `0600`, `0640`, `0644`, and `0400` must load. Unsafe modes `0660`, `0606`, `0664`, `0646`, and `0666` must return exactly `ConfigError::InvalidConfiguration`; accepting any of them, or failing for a generic I/O/JSON reason, does not satisfy the security contract.

This maps directly to CWE-732: a security-critical configuration resource must not be modifiable by unintended actors. NIST SP 800-53 Rev. 5 CM-5 requires defined and enforced logical/physical restrictions on system changes; AC-6 provides the least-privilege principle for granting only the authorizations required for the task. Here, the smallest enforceable local boundary is write authority over the reviewed policy file.

## Scope and residual risk

This decision does not add runtime policy mutation, directory-ownership policy, secret distribution, sandbox execution, reusable egress control, LLM orchestration, or static package analysis. Those remain outside this bounded context. It also does not claim immutable storage, signature verification, or a complete cross-platform ACL model. The next independent audit-path hardening work is tracked separately and must not be folded into this configuration-loader slice.

The USENIX papers are linked to their publisher copies rather than vendored into this repository. Their published reproduction terms are narrower than an unrestricted software-repository redistribution grant, so the repository preserves citation and traceability without copying the PDFs.

## References

Borisov, N., Johnson, R., Sastry, N., & Wagner, D. (2005). Fixing races for fun and profit: How to abuse atime. *14th USENIX Security Symposium*. https://www.usenix.org/conference/14th-usenix-security-symposium/fixing-races-fun-and-profit-how-abuse-atime

Dean, D., & Hu, A. J. (2004). Fixing races for fun and profit: How to use access(2). *13th USENIX Security Symposium*. https://www.usenix.org/conference/13th-usenix-security-symposium/fixing-races-fun-and-profit-how-use-access2

MITRE. (2026). *CWE-732: Incorrect permission assignment for critical resource (CWE 4.20)*. https://cwe.mitre.org/data/definitions/732.html

National Institute of Standards and Technology. (2020). *Security and privacy controls for information systems and organizations* (NIST Special Publication 800-53 Rev. 5). https://doi.org/10.6028/NIST.SP.800-53r5
