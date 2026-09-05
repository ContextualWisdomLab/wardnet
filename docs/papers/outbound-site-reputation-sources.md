# Outbound site reputation: research and source traceability

Reviewed 2026-09-05. This register supports the [ADR](../adr/2026-09-05-outbound-site-reputation-engine.md) and [design](../superpowers/specs/2026-09-05-outbound-site-reputation-design.md). Engineering requirements and benchmark targets are Wardnet proposals, not claims that the cited systems or this repository already implement them.

## R1. DNS reputation research

Antonakakis, M., Perdisci, R., Dagon, D., Lee, W., & Feamster, N. (2010). Building a dynamic reputation system for DNS. In *19th USENIX Security Symposium*. USENIX Association. https://www.usenix.org/conference/usenixsecurity10/building-dynamic-reputation-system-dns

Author-group overview: https://astrolavos.gatech.edu/2010/08/11/Building_a_Dynamic_Reputation_System_for_DNS/

**Application:** Notos is relevant evidence that DNS reputation is a security-analysis problem, not a crawler-quality metric. Wardnet therefore keeps temporal evidence and separates address observations from domain assessment. **Limit:** This proposal does not reproduce Notos, adopt its trained model, or transfer its reported accuracy to Wardnet. Source-family and time-separated evaluation are project safeguards, not assertions that a feed match achieves those research results.

## R2. Passive DNS analysis

Bilge, L., Kirda, E., Kruegel, C., & Balduzzi, M. (2011). EXPOSURE: Finding malicious domains using passive DNS analysis. In *Network and Distributed System Security Symposium*. Internet Society. https://www.ndss-symposium.org/ndss2011/exposure-finding-malicious-domains-using-passive-dns-analysis/

Author-institution record: https://www.eurecom.fr/en/publication/3281

**Application:** The work concerns malicious-domain identification from passive DNS behavior. It motivates retaining observation provenance and evaluating detection over time rather than declaring every unseen domain benign. **Limit:** Passive-DNS analytics and a learned detector are not required for the first deterministic, proven-feed-based Wardnet implementation. No published detection rate is a product acceptance result.

## R3. Threat-intelligence semantics

Jordan, B., Piazza, R., & Darley, T. (Eds.). (2021, June 10). *STIX version 2.1* (OASIS Standard). OASIS Open. https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html

**Application:** Sections on common properties, versioning, indicators, and markings distinguish creator confidence, validity, revocation, and distribution restrictions. Wardnet must preserve these dimensions instead of reducing all imported data to a permanent numeric score. Missing confidence is not a safety statement. **Limit:** A STIX-shaped payload is not automatically authentic, current, trustworthy, or authorized for a particular tenant; source admission remains necessary. Only supported patterns become enforcement material.

## R4. Protective DNS operational guidance

National Cyber Security Centre. (n.d.). *Protective DNS for the private sector*. Retrieved September 5, 2026, from https://www.ncsc.gov.uk/guidance/protective-dns-for-private-sector

**Application:** Protective DNS addresses access to malicious destinations and provides operational security evidence. This supports Wardnet's outbound-security use case and the need to connect enforcement with monitoring and false-positive handling. **Limit:** DNS filtering is one control, not proof of complete traffic interception or visibility into encrypted URL paths. The proposed PEP and deployment acceptance must establish their own coverage.

## R5. Malware URL intelligence

abuse.ch. (n.d.). *URLhaus API*. Retrieved September 5, 2026, from https://urlhaus.abuse.ch/api/

**Application:** A proven malware-URL source is a candidate input. A URL observation and a derived hostname block have different scopes; the adapter must retain that distinction and source notices. **Limit:** Eligibility, current API authentication, polling bounds and commercial use must be checked before enabling a provider. Community access is not an unlimited commercial redistribution grant. Do not send private per-request URLs to an external provider in v1.

## R6. IOC lifecycle and provider access

abuse.ch. (n.d.). *ThreatFox API*. Retrieved September 5, 2026, from https://threatfox.abuse.ch/api/

**Application:** ThreatFox documents authenticated access and expiration of older indicators, illustrating why an imported IP must not remain a timeless verdict. Preserve source status and provenance rather than extending validity at every refresh. **Limit:** Provider-specific expiration is not a universal TTL for every source. Use the current access/usage contract, maintain TLS verification, and obtain any required commercial entitlement before production ingestion.

## Repository evidence and ownership

Inspected protected Wardnet commit: `5829a0f08d78de464dd24393ce5d0f25fba9d126`.

- [AGENTS.md](https://github.com/ContextualWisdomLab/wardnet/blob/5829a0f08d78de464dd24393ce5d0f25fba9d126/AGENTS.md): Rust-first, proven engines, configuration, research and governance constraints.
- [Architecture](https://github.com/ContextualWisdomLab/wardnet/blob/5829a0f08d78de464dd24393ce5d0f25fba9d126/docs/architecture.md) and [core models](https://github.com/ContextualWisdomLab/wardnet/blob/5829a0f08d78de464dd24393ce5d0f25fba9d126/crates/waf-ids-core/src/lib.rs): actual gateway, ingestion, DNSBL and event baseline.
- [Wardnet #136](https://github.com/ContextualWisdomLab/wardnet/pull/136) and [#115](https://github.com/ContextualWisdomLab/wardnet/pull/115): preserve consumer/feed evidence without a duplicate transport-policy owner.
- [EgressWeave #237](https://github.com/ContextualWisdomLab/EgressWeave/issues/237): immutable Rust-compatible transport authorization contract. The [GitHub Releases listing](https://api.github.com/repos/ContextualWisdomLab/EgressWeave/releases?per_page=1) returned an empty array at review time; this observation is not a claim about every possible package registry.
- [Wardnet #167](https://github.com/ContextualWisdomLab/wardnet/pull/167) and [#170](https://github.com/ContextualWisdomLab/wardnet/pull/170): ongoing MISP lifecycle and source-severity repairs, not presumed protected behavior.
- [Wardnet #130](https://github.com/ContextualWisdomLab/wardnet/pull/130): sole product-gap ledger writer. The design PR adds separate documents and does not edit that ledger.

Open PR/issue descriptions are dependency and ownership evidence as inspected on 2026-09-05, not immutable API releases or proof of shipped implementation. Re-read them before implementation.

## Research artifact and redistribution decision

No third-party PDF is committed in this documentation slice. USENIX makes the Notos paper openly accessible, but the reviewed page did not establish an explicit public-repository redistribution grant. The EXPOSURE institutional [copyright notice](https://www.eurecom.fr/en/publication/3281/copyright) permits personal use; that is not treated as permission to redistribute the full paper in this repository. Follow AGENTS.md's cite/link/original-summary fallback rather than infer rights from download availability.

The STIX standard is cited in its normative HTML form; it is a standard, not an academic-paper substitute. Provider datasets, API examples and malicious samples are not vendored. Source-specific licensing, attribution, access controls and distribution markings must be recorded by any future adapter. This register contains original summaries and bibliographic references, not copied papers or datasets.
