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
- a separate `PolicyActionV1`, because a Wardnet reputation allow only permits continuation to independent gates and is never executable EgressWeave transport authorization.

Rejected alternatives are: treating `unknown` as benign, aggregating producer confidence into an invented probability, using HTTP success as an authorization signal, or allowing business authorization to override adverse evidence. These choices would erase provenance or conflate observation, policy, and enforcement authority.

Load-balancing literature is intentionally not used to justify this contract shape. This crate performs no scheduling, dispatch, network I/O, or executable load balancing, so latency/implementation-overhead results from load-balancing systems are not causal evidence for the v1 data model. Performance and concurrency research becomes applicable when the evaluator/cache and measured deployment path are implemented; the implementation plan requires those later slices to profile and benchmark the real path rather than pre-justify this transport-neutral schema with unrelated systems results.

## Source handling

The ACM article is cited by DOI and bibliographic metadata only. Its publisher access is not assumed to grant redistribution rights, so no article PDF is copied into this repository. NIST CSF 2.0 is linked to its official NIST publication and DOI. Future local copies must be added only when redistribution terms are verified.

## References

Chandola, V., Banerjee, A., & Kumar, V. (2009). Anomaly detection: A survey. *ACM Computing Surveys, 41*(3), Article 15. https://doi.org/10.1145/1541880.1541882

Pascoe, C., Quinn, S., & Scarfone, K. (2024). *The NIST Cybersecurity Framework (CSF) 2.0* (NIST CSWP 29). National Institute of Standards and Technology. https://doi.org/10.6028/NIST.CSWP.29
