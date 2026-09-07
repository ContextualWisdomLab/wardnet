# Source-generation membership traceability

## Problem and boundary

`SourceSnapshotV1.source_id` is stable across source refreshes, while `source_generation` identifies one immutable completed admission generation. Binding an evidence record only to `source_id` therefore cannot prove which completed refresh admitted that record. A record retained from generation N could be replayed into generation N+1 while still satisfying source-identity and receive-before-completion checks.

This is a Wardnet evidence/provenance invariant. The crate does not fetch reputation sources, parse destinations, resolve DNS, authorize peers or redirects, select proxies, establish TLS, or authorize resources. Those executable transport concerns remain outside this bounded context. `source_generation` is an opaque admission identity supplied by the owning source-admission path; Wardnet only verifies that retained evidence membership is exact, bounded, and internally coherent.

## Decision

The public v1 snapshot authority is `EvidenceSnapshotV1`, whose records are `EvidenceSnapshotRecordV1 { source_generation, record }`. The wrapper validates its admission-only `source_generation` as nonblank text with the same 1,024-byte v1 text ceiling before that value participates in matching. Validation then delegates the existing schema, bounded-input, source-uniqueness, record, completion-order, and producer-record replay checks to the pre-existing aggregate validator. Finally, it requires each member's `(record.source_id, source_generation)` pair to match one represented completed `SourceSnapshotV1` exactly.

The original generation-unbound aggregate remains a private implementation detail only so existing validation rules can be reused rather than forked. The public `model` compatibility namespace continues to expose unaffected v1 contract types but intentionally does not expose the superseded unbound `EvidenceSnapshotV1`. This leaves one public v1 snapshot authority and prevents callers from bypassing the exact-generation invariant through an alternate constructor path.

No default or inferred generation is accepted. A missing generation fails strict decoding; a blank generation fails the bounded required-text contract; an oversized, stale, or otherwise unmatched generation fails closed before it can be accepted as completed-generation membership.

## Alternatives considered

**Stable `source_id` only — rejected.** A stable source identity says which authority family produced evidence, not which completed refresh admitted a retained record. It leaves the stale-generation replay demonstrated by the hostile regression representable.

**Infer membership from `received_at_unix <= completed_at_unix` — rejected.** Temporal ordering is necessary but not sufficient. An older retained record can precede the completion time of a later generation without belonging to that generation. Time ordering therefore cannot establish exact provenance membership.

**Add `source_generation` directly to `EvidenceRecordV1` — rejected for v1.** `EvidenceRecordV1` preserves producer evidence and producer-native record identity, while source-generation membership is Wardnet admission provenance. The wrapper keeps those concepts separate and avoids pretending the producer supplied Wardnet's refresh identity.

**Keep both public snapshot aggregates — rejected.** Two public v1 authorities would let a consumer choose the weaker generation-unbound representation and silently evade the new invariant. Compatibility is preserved only for unaffected model types.

**Leave wrapper generation text unbounded because represented source snapshots are bounded — rejected.** Matching an untrusted wrapper value against bounded source identities still permits an oversized value to reach the membership scan and creates a separate malformed-input behavior. The admission-only field is therefore bounded before matching instead of relying on eventual mismatch.

## Verification evidence

The hostile source-generation regression uses a completed `source-generation-43` snapshot with an otherwise valid record explicitly bound to `source-generation-42`; the same record bound to generation 43 is the control. The test-only RED at `8246d42952e9447480280690647ebe23d3695d65` failed against unchanged parent production.

A second public-authority RED at `51a1d6d8329c99fc6a1e892e9150164dcddb641d` retained the generation tests and required `wardnet_reputation_core::model::EvidenceSnapshotV1` not to compile. Hosted CI `34150552749` passed the ordinary workspace tests and then failed the `compile_fail` doctest because the obsolete aggregate was still public. The causal repair keeps unaffected `model::...` compatibility while excluding only that superseded snapshot authority.

Fresh review then found the wrapper's new `source_generation` field itself was not bounded before matching. Test-only RED `a2cfd2e108ec8e75c54dd896225809a7c1ccabb5` supplies 1,025 bytes. Hosted CI `34152014206`, Rust job `101836077859`, acquired GitHub-hosted Ubuntu 24.04, passed checkout/toolchain/fmt and the preceding tests, then failed the hostile assertion because the implementation returned `MissingSourceSnapshot` instead of the required `BoundExceeded("snapshot_record.source_generation")`. Causal production repair `d86d8f2a18cce69f3bebb80ec3ef01f38db74ea7` applies the explicit required-text ceiling before membership matching. Exact-current GREEN evidence belongs in the pull request/run record and must not be inferred from predecessor heads.

## Standards traceability

NIST defines provenance as the chronology of origin, development, ownership, location, and changes associated with systems, components, and data. That supports retaining an explicit relationship between admitted evidence and the exact completed source generation represented by a snapshot. NIST does **not** prescribe Wardnet's `source_generation`, wrapper type, or validation algorithm; those are local bounded-context decisions for making provenance mechanically verifiable rather than merely descriptive.

NIST SP 800-218 SSDF 1.1 remains the final publication used as the normative secure-development reference for this candidate. PW.5.1 includes input validation among secure implementation practices, supporting strict decoding and explicit bounded validation before scope-bearing identity participates in matching. NIST published SP 800-218 Rev. 1 / SSDF 1.2 as an Initial Public Draft on December 17, 2025; its comment period is closed, but NIST still lists that revision as Draft as of this review, so Wardnet does not present the draft as final normative authority. The candidate was checked against that newer draft direction without replacing the final 1.1 citation.

The generation rule supplements, rather than replaces, the existing timestamp, provenance-reference, source-policy, and evidence-lifecycle checks.

## References

National Institute of Standards and Technology. (2026). *Provenance*. Computer Security Resource Center Glossary. Retrieved September 8, 2026, from https://csrc.nist.gov/glossary/term/provenance

Booth, H., Ogata, M., Kent, K., Souppaya, M., & Dodson, D. (2025). *Secure Software Development Framework (SSDF) version 1.2: Recommendations for mitigating the risk of software vulnerabilities* (NIST Special Publication 800-218 Rev. 1, Initial Public Draft). National Institute of Standards and Technology. https://csrc.nist.gov/pubs/sp/800/218/r1/ipd

Souppaya, M., Scarfone, K., & Dodson, D. (2022). *Secure Software Development Framework (SSDF) version 1.1: Recommendations for mitigating the risk of software vulnerabilities* (NIST Special Publication 800-218). National Institute of Standards and Technology. https://doi.org/10.6028/NIST.SP.800-218
