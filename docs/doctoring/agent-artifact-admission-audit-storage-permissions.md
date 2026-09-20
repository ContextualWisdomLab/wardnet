# Agent Artifact Admission audit-storage permission authority

Status: Proposed implementation evidence for issue #256 / PR #257. This document does not widen Wardnet into execution isolation, outbound transport enforcement, Agent/LLM orchestration, or static package analysis.

## Problem and exact evidence

Wardnet's Agent Artifact Admission persists minimized security decisions to an append-only NDJSON file before returning an admission result. At canonical parent `eec36424a2a4cd3e08e6ab61af1e112e387f2ac4`, the Linux file sink opened its target with `O_NOFOLLOW | O_NONBLOCK`, `O_APPEND`, `O_CREAT`, and creation mode `0600`, then verified only that the opened descriptor referred to a regular file.

That creation mode is insufficient authority for an already-existing inode. Linux `open(2)` applies the supplied mode when a file is created; opening an existing regular file does not retroactively narrow its permissions. A pre-existing audit target readable or writable by group/other principals could therefore receive Agent Artifact Admission evidence even though Wardnet had not established exclusive audit-storage authority.

Test-only exact `b28b72350247729d9a64bf2c9ff2e619b13a5ddd` materialized the hostile RED on hosted Ubuntu 24.04. CI `34456998108`, job `102805608039`, reached the real workspace test suite and failed only the new audit-storage regression: a pre-existing mode `0666` regular file was accepted and appended instead of failing closed. The owner-only `0600` positive control passed. This isolates the defect from runner availability, symlink handling, FIFO handling, serialization, and ordinary append semantics.

## Authority and constraints

The affected resource is Wardnet-owned security evidence. The record carries actor, workspace, artifact identity, policy revision and admission decision metadata. Its confidentiality and integrity therefore cannot depend on an operator having manually repaired filesystem mode bits before process start.

The repair must preserve the existing single-open property. A pathname metadata check followed by a later open would reintroduce a time-of-check/time-of-use interval. A post-open `chmod` is also rejected: silently mutating externally provisioned storage would hide deployment drift, can surprise storage ownership policy, and is not needed to establish a fail-closed admission boundary.

`quarantine-sandbox-runtime` remains authoritative for hostile execution/isolation and effective runtime environment; EgressWeave remains authoritative for executable outbound transport; `contextual-orchestrator` remains authoritative for Agent/LLM orchestration; AppGuardrail remains authoritative for static package/security analysis. This change governs only Wardnet's own file-backed admission evidence sink.

## Decision

On Linux, retain the existing `O_NOFOLLOW | O_NONBLOCK | O_APPEND` acquisition and `0600` creation mode. Immediately after the single open and before any record write, inspect metadata from that same descriptor. The descriptor is admissible only when it is a regular file and `mode & 0o077 == 0`. Any group/other read, write or execute permission fails closed as storage unavailable. An already-existing owner-only `0600` file remains valid, and a newly created target remains `0600` subject to the process umask.

The implementation does not call `chmod`, does not replace the path, does not follow a second pathname lookup, and does not weaken the existing symlink/FIFO/special-file controls. Platforms without Wardnet's tested native file-authority contract continue to fail closed rather than claiming equivalent ACL semantics.

## Alternatives considered

Allowing group-readable `0640` or world-readable `0644` was rejected because the persisted record contains security decision and actor/workspace metadata, not public telemetry. Allowing group-writable storage was rejected because another principal could alter the evidence stream. Automatically tightening permissions with `chmod` was rejected because it conceals unsafe deployment state and changes external resource policy. Path-based preflight metadata was rejected because a second open would break the existing same-descriptor authority invariant.

## Security and operational effect

The selected invariant converts unsafe pre-existing storage from an implicit trust assumption into an explicit startup/write-time failure. This is intentionally availability-sacrificing: an insecure audit target prevents durable evidence and therefore prevents an admission response from being treated as successful. Operators receive the existing non-secret storage failure rather than path, payload or credential material.

The change does not prove filesystem-owner identity, immutable storage, remote log retention, SIEM ingestion, or production retention policy. Those remain separate controls. Future support for richer ACLs or non-Linux platforms requires a separately tested native authority model rather than weakening this Unix mode-bit contract.

## Acceptance

The exact repaired head must demonstrate all of the following on hosted Linux before integration:

- pre-existing regular files with representative group/other permission bits such as `0666`, `0640`, and `0604` are rejected without appending bytes;
- a pre-existing owner-only `0600` regular file remains appendable;
- newly created audit storage remains owner-only;
- existing symlink, FIFO, special-file, bounded-record, flush and `sync_data` behavior remains intact;
- exact-head CI and fuzz gates are terminal green, with no unresolved valid review finding;
- the entire RED, causal source delta, tests and evidence are transferred into canonical Agent Artifact Admission PR #129 or a verified successor by ordinary non-force integration.

## Traceability

National Institute of Standards and Technology. (2020). *Security and privacy controls for information systems and organizations (NIST Special Publication 800-53 Rev. 5)*. https://doi.org/10.6028/NIST.SP.800-53r5 — AU-9 requires protection of audit information and audit logging tools from unauthorized access, modification, and deletion.

National Institute of Standards and Technology. (2024). *Protecting controlled unclassified information in nonfederal systems and organizations (NIST Special Publication 800-171 Rev. 3)*. https://doi.org/10.6028/NIST.SP.800-171r3 — requirement 03.03.08 maps to AU-9 protection of audit information.

MITRE. (2026). *CWE-732: Incorrect Permission Assignment for Critical Resource (CWE 4.20)*. https://cwe.mitre.org/data/definitions/732.html — overly broad permissions on security-critical resources permit unintended read or modification; insecure resource permissions should be rejected or constrained deliberately.

Linux man-pages project. (2026). *open(2) — Linux manual page*. https://man7.org/linux/man-pages/man2/open.2.html — `O_NOFOLLOW` rejects a trailing symbolic link, `O_NONBLOCK` avoids blocking semantics where applicable such as FIFOs, and the `mode` argument governs creation permissions rather than retroactively constraining an already-existing inode.
