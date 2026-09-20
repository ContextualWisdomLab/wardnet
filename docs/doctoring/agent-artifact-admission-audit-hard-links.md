# Agent Artifact Admission audit hard-link authority

Status: Proposed evidence note for Wardnet issue #258 and PR #259.

## Problem

Wardnet's file-backed Agent Artifact Admission audit sink is a security-evidence boundary. Final-symlink refusal, regular-file validation, and owner-only Unix permission bits are necessary but do not distinguish an ordinary pathname from a hard link to another pathname for the same inode. Linux exposes the inode link count through descriptor metadata; a count greater than one proves that the opened file has another hard-link name.

For this append-only evidence path, accepting a multiply linked inode would let one append through the configured audit pathname mutate the same file visible under another pathname. The relevant invariant is therefore narrower than general filesystem hardening: immediately after Wardnet's existing single secure open, the opened regular file must be owner-only and have exactly one hard link before an audit record is written.

## Decision

On Linux, `FileAuditSink::open_append_only` reads metadata from the descriptor returned by the existing `O_NOFOLLOW | O_NONBLOCK | O_APPEND` open and fails closed unless all of the following hold:

- the descriptor refers to a regular file;
- group and other permission bits are absent (`mode & 0o077 == 0`);
- `st_nlink == 1`.

The implementation does not `chmod`, unlink, replace, or perform a second pathname lookup to repair externally provisioned storage. This keeps configuration drift observable and avoids adding a pathname preflight as security authority. The existing non-Linux fail-closed behavior remains unchanged because equivalent tested native file-authority semantics have not been established there.

This decision covers pre-existing hard-link aliasing at the audited open boundary. It does not claim that a link-count observation is a general substitute for directory ownership, mount policy, runtime isolation, or filesystem-specific controls; those remain deployment/runtime concerns outside this Wardnet bounded context.

## Evidence and traceability

The hosted RED at exact test-only commit `b992cdb0e3cc42cd48427072373010fcde798a78` ran on Ubuntu 24.04 in CI run `34458676152`, job `102811040900`. Formatting succeeded, the full workspace reached `audit_contract`, and only `file_sink_rejects_hard_linked_owner_only_regular_file` failed. The assertion failed because the current sink accepted the multiply linked owner-only inode and attempted the append. This isolates the missing link-count invariant rather than runner startup, formatting, ordinary append behavior, symlink handling, FIFO handling, or permission-bit enforcement.

CWE-62 describes insufficient accounting for a UNIX hard link whose name refers to a target outside the intended control sphere. CWE 4.20 is the current CWE release as of this note. Linux `inode(7)` defines `st_nlink`/`stx_nlink` as the number of hard links to a file, and `link(2)` defines creation of an additional hard link to an existing file. NIST SP 800-53 Rev. 5 AU-9 supplies the broader control objective to protect audit information and audit tooling; it does not prescribe the `st_nlink == 1` implementation. The Wardnet invariant is the product-specific mechanism selected to support that objective for this file sink.

## References

MITRE. (2026). *CWE-62: UNIX hard link* (CWE List Version 4.20). Common Weakness Enumeration. https://cwe.mitre.org/data/definitions/62.html

National Institute of Standards and Technology. (2020). *Security and privacy controls for information systems and organizations* (NIST Special Publication 800-53, Revision 5). U.S. Department of Commerce. https://doi.org/10.6028/NIST.SP.800-53r5

Kerrisk, M. (Ed.). (2026). *inode(7) — Linux manual page*. Linux man-pages project. https://man7.org/linux/man-pages/man7/inode.7.html

Kerrisk, M. (Ed.). (2026). *link(2) — Linux manual page*. Linux man-pages project. https://man7.org/linux/man-pages/man2/link.2.html
