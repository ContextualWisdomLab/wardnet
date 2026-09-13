# Agent Artifact Admission configuration-file integrity

## Decision under review

Wardnet treats the Agent Artifact Admission configuration as policy authority, not as a secret. The file contains the reviewed policy revision, executable allowlist, workspace-manifest digests, and exact artifact coordinates. Read-only group or other visibility therefore does not change admission authority, but group or other write authority does: an unintended writer could replace an approved digest, artifact coordinate, or executable and thereby alter the result of a later admission decision.

Credentials are a separate authority-bearing input. Their confidentiality and integrity both matter because the document carries the admission endpoint bearer token. A filesystem pathname is not itself sufficient evidence that either policy or credential bytes came from the intended local object.

## Descriptor-bound acquisition

On Linux, both loaders now use one read-only open with `O_NOFOLLOW | O_NONBLOCK`, then inspect the resulting descriptor before materializing bytes. A final symbolic link is therefore rejected by the open operation rather than followed. A FIFO can be opened for inspection without waiting for a writer, after which Wardnet rejects it because the opened descriptor is not a regular file. Other special-file types are rejected by the same regular-file invariant.

This order is deliberate. POSIX.1-2024 specifies that `O_NOFOLLOW` causes `open()` to fail when the final pathname component is a symbolic link and that a read-only FIFO opened with `O_NONBLOCK` returns without waiting for a writer. The same standard notes that no-follow behavior avoids races in which a pathname is substituted with a symbolic link to a sensitive object. MITRE CWE-59 classifies security-sensitive link following as improper link resolution before file access and identifies confidentiality, integrity and access-control consequences.

After the descriptor is acquired, the policy loader rejects any group/other write bit (`mode & 0o022 != 0`) as `ConfigError::InvalidConfiguration`. This intentionally permits read-only modes such as `0644` while rejecting policy-mutation authority such as `0664` or `0666`. The credential loader is stricter and rejects any group/other permission bit (`mode & 0o077 != 0`) because credential confidentiality is itself a requirement. Both checks use metadata from the already-open regular-file descriptor.

The same-open-handle sequence also preserves the earlier TOCTOU decision. A path-level permission or file-type check followed by a separate open would create a check/use interval in which the pathname could resolve to a different object. Dean and Hu (2004) formalize this class of filesystem race, while Borisov et al. (2005) show why probabilistic attempts to make such races difficult do not provide a sound authority boundary. Wardnet therefore does not add a pathname pre-check as a substitute for descriptor-bound acquisition.

On targets other than Linux, this version fails closed because Wardnet has not defined and tested an equivalent no-follow, nonblocking open plus native ACL authority contract. The file-backed audit sink already follows the same compatibility boundary. Adding another platform is a separate compatibility increment and must preserve equivalent link, special-file, permission and bounded-read guarantees rather than silently weakening them.

## Executable acceptance contract

`config_file_permissions_contract.rs` creates one valid configuration, applies safe and unsafe Linux modes to the same fixture, and calls the public loader. Safe modes `0600`, `0640`, `0644`, and `0400` must load. Unsafe modes `0660`, `0606`, `0664`, `0646`, and `0666` must return exactly `ConfigError::InvalidConfiguration`; accepting any of them, or failing for a generic JSON reason, does not satisfy the security contract.

`local_file_authority_contract.rs` covers the object-identity boundary independently of permission bits. A mode-`0600` credential target and a mode-`0644` policy target reached only through final symbolic links must both fail closed. Its Linux FIFO helper runs in a child process with a fixed deadline so a regression cannot hang the test job indefinitely; both loaders must reject the FIFO promptly before any attempt to parse it as JSON.

These tests complement rather than replace the append-only audit-path contracts. The audit sink and the two admission input readers now use the same Linux acquisition properties while retaining different write/read and confidentiality invariants appropriate to their bounded responsibilities.

## Control mapping and scope

The permission portion maps directly to CWE-732: a security-critical configuration resource must not be modifiable by unintended actors. The pathname-object portion maps to CWE-59. NIST SP 800-53 Rev. 5 CM-5 requires defined and enforced restrictions on system changes, while AC-6 provides the least-privilege principle for granting only the authorizations required for the task. Here, the smallest enforceable local boundary is: acquire one non-symlink, nonblocking regular-file descriptor; verify the relevant local authority bits on that descriptor; then read only within the fixed byte budget.

This decision does not add runtime policy mutation, directory-ownership policy, secret distribution, hostile workload execution, reusable egress control, LLM orchestration, or static package analysis. Those remain outside this bounded context. It does not claim immutable storage, signature verification, protection against a malicious privileged filesystem administrator, or a complete cross-platform ACL model.

The USENIX papers are linked to their publisher copies rather than vendored into this repository. Their published reproduction terms are narrower than an unrestricted software-repository redistribution grant, so the repository preserves citation and traceability without copying the PDFs.

## References

Borisov, N., Johnson, R., Sastry, N., & Wagner, D. (2005). Fixing races for fun and profit: How to abuse atime. *14th USENIX Security Symposium*. https://www.usenix.org/conference/14th-usenix-security-symposium/fixing-races-fun-and-profit-how-abuse-atime

Dean, D., & Hu, A. J. (2004). Fixing races for fun and profit: How to use access(2). *13th USENIX Security Symposium*. https://www.usenix.org/conference/13th-usenix-security-symposium/fixing-races-fun-and-profit-how-use-access2

IEEE & The Open Group. (2024). *open, openat — open file*. In *POSIX.1-2024*. https://pubs.opengroup.org/onlinepubs/9799919799/functions/open.html

MITRE. (2026). *CWE-59: Improper link resolution before file access ('link following') (CWE 4.20)*. https://cwe.mitre.org/data/definitions/59.html

MITRE. (2026). *CWE-732: Incorrect permission assignment for critical resource (CWE 4.20)*. https://cwe.mitre.org/data/definitions/732.html

National Institute of Standards and Technology. (2020). *Security and privacy controls for information systems and organizations* (NIST Special Publication 800-53 Rev. 5). https://doi.org/10.6028/NIST.SP.800-53r5
