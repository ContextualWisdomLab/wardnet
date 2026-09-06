# Reputation contract research and standards traceability

This note records the evidence boundary for `wardnet-reputation-core`. The crate defines transport-neutral Wardnet domain contracts; it is not an anomaly detector, feed client, executable egress authority, or transport policy engine.

## Decision rationale

NIST Cybersecurity Framework (CSF) 2.0 treats Detect as outcomes for finding and analyzing possible cybersecurity attacks and compromises while leaving implementation mechanisms to the adopting organization. Wardnet therefore keeps the observed security assessment, evidence-authority health, and policy action as separate fields instead of treating a detector output as self-executing authorization.

Chandola, Banerjee, and Kumar (2009) show that anomaly-detection techniques depend on domain-specific assumptions about what distinguishes normal from anomalous behavior. That supports a conservative contract boundary here: absence of eligible adverse evidence is `unknown`, not evidence of benignness; producer confidence is retained as producer metadata rather than converted into a Wardnet probability; and an adverse classification remains traceable to reviewed evidence. The paper does **not** define Wardnet's `KnownMalicious`, `Suspicious`, or `Unknown` vocabulary. Those are Wardnet bounded-context terms for evidence state and must not be presented as categories from the paper.

The v1 contract therefore chooses:

- `KnownMalicious` only for eligible reviewed evidence that asserts a hard threat within explicit scope;
- `Suspicious` for adverse evidence that does not establish the hard-threat condition;
- `Unknown` when no eligible adverse match establishes safety;
- a separate `EvidenceHealthV1` so source outage or expiry can fail closed without rewriting the underlying assessment;
- a separate `PolicyActionV1`, because a Wardnet reputation allow only permits continuation to independent gates and is never executable EgressWeave transport authorization;
- an explicit `policy_mode=protect` binding on `DecisionEnvelopeV1`, because the Proposed protect contract and monitor/shadow semantics are different authorities. A monitor result may describe what policy would have done, but it cannot be decoded or validated as a protect grant merely because its assessment and action fields are otherwise coherent.

Rejected alternatives are: treating `unknown` as benign, aggregating producer confidence into an invented probability, using HTTP success as an authorization signal, or allowing business authorization to override adverse evidence. These choices would erase provenance or conflate observation, policy, and enforcement authority.

Load-balancing literature is intentionally not used to justify this contract shape. This crate performs no scheduling, dispatch, network I/O, or executable load balancing, so latency/implementation-overhead results from load-balancing systems are not causal evidence for the v1 data model. Performance and concurrency research becomes applicable when the evaluator/cache and measured deployment path are implemented; the implementation plan requires those later slices to profile and benchmark the real path rather than pre-justify this transport-neutral schema with unrelated systems results.

## Wire-schema compatibility and fail-closed decoding

The v1 wire structs accept only fields declared by the exact `wardnet.reputation.v1` schema. Serde's default forward-compatible behavior of ignoring unknown struct fields is deliberately rejected at this security boundary. An unrecognized scope-bearing field can otherwise combine with an omitted optional field and change semantics. The hostile regression demonstrates the concrete case: `tenant_ids` would be ignored while absent `tenant_id` deserializes as `None`, and `None` is the contract state that may represent globally applicable evidence. That is a scope-widening failure, not harmless extension data.

The same rule applies to reviewed source eligibility. A source policy must now state whether it is reviewed for `all_authenticated_tenants` or an `explicit_tenant_set`; an omitted tenant-scope declaration is invalid, an explicit set cannot be empty, and an all-tenant declaration cannot smuggle a contradictory tenant list. This closes the gap between authenticated tenant binding and source eligibility without treating a missing restriction as an implicit organization-wide grant. It also keeps the tenant decision inside Wardnet's reputation-policy contract rather than moving identity authentication into this crate.

MITRE CWE-20 explicitly calls out missing and extra inputs as properties that input validation should consider and recommends accepting only values that strictly conform to the intended specification. NIST SP 800-218 SSDF 1.1 PW.5.1 likewise includes validating all inputs as a secure-coding implementation example. Accordingly, every v1 wire struct uses strict unknown-field rejection. A producer or consumer that needs a new security-relevant field must negotiate a new compatible schema version instead of relying on a v1 reader to discard it.

The rejected alternative was permissive unknown-field decoding for forward compatibility. It was rejected because this contract contains optional scope, marking, and evidence metadata whose absence has domain meaning; silently discarding a misspelled or future field can therefore convert an explicit restriction into absence. Exact versioning is the safer and more reviewable compatibility mechanism.

As of 2026-09-06, NIST SP 800-218 Rev. 1 / SSDF 1.2 is still an Initial Public Draft rather than a final replacement. It is tracked for forward awareness, while the final SSDF 1.1 remains the normative NIST citation used for this implemented decision.

## Business-authorization evidence binding

A `business_authorization` reason is security-relevant policy evidence, not a magic enum that can create authority by itself. NIST CSF 2.0 PR.AA-05 describes access permissions, entitlements, and authorizations as things that are defined in policy, managed, enforced, reviewed, and constrained by least privilege. NIST SP 800-53 Rev. 5, current Release 5.2.0, keeps access enforcement and audit/accountability as explicit control families; AC-3 requires approved authorizations to be enforced and AU controls require enough event content to support accountability. Those publications do not prescribe Wardnet's wire fields, so this implementation is a local control mapping rather than a claim that NIST defines this schema.

`BusinessAuthorizationBindingV1` therefore makes an allow explainable and bounded by carrying an immutable authorization identity and nonzero revision; the exact reviewed Wardnet policy identity and immutable policy revision; authority and origin; exact tenant, workload, purpose, profile, canonical destination subject, and the external canonicalization profile/version under which that subject was reviewed; validity and revocation state; approver and ticket references; and bounded provenance. Validation fails closed when the binding is missing, attached to a decision that does not use it, revoked, outside its validity interval, lacks provenance, mismatches any authenticated context dimension or canonicalization identity, was reviewed for a different policy identity or revision, or expires before the decision envelope does. A policy replacement, canonicalization-profile change, or canonicalization-version change cannot inherit an older business grant without a newly reviewed binding even when the resulting opaque subject string happens to remain equal.

The exact-subject and canonicalization-identity comparison deliberately consumes the `DestinationSubjectV1`, `canonicalization_profile`, and `canonicalization_version` already supplied to Wardnet by the owning canonicalization boundary. Wardnet does not interpret the external profile, reimplement its normalization rules, parse URLs, resolve DNS, validate peers, follow redirects, choose proxies, establish TLS, or authorize transport. Those executable and canonicalization semantics remain EgressWeave-owned; Wardnet only binds its own authorization evidence to the immutable external identity it actually reviewed. Likewise, the binding cannot override `KnownMalicious`, `Suspicious`, expired required evidence, or unavailable required authority: the existing adverse and authority-health fail-closed checks retain precedence before business-authorization validation.

Rejected alternatives were: allowing `reason=business_authorization` with no evidence; accepting tenant-only or host-only grants that silently widen workload/purpose/profile scope; allowing a grant reviewed under one policy revision to survive policy replacement; binding only the opaque subject while allowing its external canonicalization semantics to drift; allowing a decision to outlive its authorization; and treating an approver/ticket string alone as provenance. Each would make the serialized decision look more authoritative than the evidence actually supports.

## Source handling

The ACM article is cited by DOI and bibliographic metadata only. Its publisher access is not assumed to grant redistribution rights, so no article PDF is copied into this repository. NIST CSF 2.0, SP 800-53 Rev. 5 Release 5.2.0, and SSDF 1.1 are linked to official NIST publications. Future local copies must be added only when redistribution terms are verified.

## References

Chandola, V., Banerjee, A., & Kumar, V. (2009). Anomaly detection: A survey. *ACM Computing Surveys, 41*(3), Article 15. https://doi.org/10.1145/1541880.1541882

Joint Task Force. (2020). *Security and privacy controls for information systems and organizations* (NIST Special Publication 800-53 Rev. 5; Release 5.2.0, August 27, 2025). National Institute of Standards and Technology. https://doi.org/10.6028/NIST.SP.800-53r5

MITRE. (n.d.). *CWE-20: Improper input validation* (Version 4.20). Retrieved September 6, 2026, from https://cwe.mitre.org/data/definitions/20.html

Pascoe, C., Quinn, S., & Scarfone, K. (2024). *The NIST Cybersecurity Framework (CSF) 2.0* (NIST CSWP 29). National Institute of Standards and Technology. https://doi.org/10.6028/NIST.CSWP.29

Souppaya, M., & Scarfone, K. (2022). *Secure Software Development Framework (SSDF) version 1.1: Recommendations for mitigating the risk of software vulnerabilities* (NIST SP 800-218). National Institute of Standards and Technology. https://doi.org/10.6028/NIST.SP.800-218

Booth, H., Ogata, M., Kent, K., Souppaya, M., & Dodson, D. (2025). *Secure Software Development Framework (SSDF) version 1.2: Recommendations for mitigating the risk of software vulnerabilities* (NIST SP 800-218 Rev. 1, Initial Public Draft). National Institute of Standards and Technology. https://csrc.nist.gov/pubs/sp/800/218/r1/ipd
