# ADR 2026-09-05: Keep outbound anti-bot acquisition outside Wardnet

- Status: Proposed; documentation-only, pending PR review
- Date: 2026-09-05
- Inspected Wardnet base: `5829a0f08d78de464dd24393ce5d0f25fba9d126`
- Detailed Wardnet site-reputation proposal: [Wardnet PR #173](https://github.com/ContextualWisdomLab/wardnet/pull/173)
- Anti-bot incubation proposal: [Veilpick PR #3](https://github.com/ContextualWisdomLab/Veilpick/pull/3), stacked on Veilpick PR #1

## Context

Wardnet is the Rust-first gateway/WAF/IDS/SOC control-plane owner described by [AGENTS](../../AGENTS.md), [CLAUDE](../../CLAUDE.md), and the [architecture](../architecture.md). It owns gateway admission and enforcement, security evidence and policy, Agent Artifact Admission, and the lifecycle of Wardnet security decisions. Implementation language does not make browser acquisition, challenge solving, session camouflage, or anti-bot navigation part of that bounded context.

The first version of this proposal also placed destination site reputation outside Wardnet. A later explicit product request, represented by Wardnet PR #173, assigns destination maliciousness, evidence lifecycle, organizational admission policy, and SOC accountability to Wardnet while retaining EgressWeave as the reusable outbound URL/address/DNS/peer/redirect/proxy/TLS/resource-policy owner. This ADR therefore narrows its decision to anti-bot acquisition only instead of creating a competing site-reputation authority.

## Decision

### 1. Keep browser acquisition and challenge handling outside Wardnet

| Capability | Canonical responsibility | Wardnet boundary |
| --- | --- | --- |
| Inbound request inspection and gateway enforcement | Wardnet plus reviewed security-engine integrations | Own and enforce |
| Agent artifact/workload admission and security evidence | Wardnet | Own and enforce |
| Destination maliciousness/reputation policy and SOC evidence | Wardnet, through the bounded design in PR #173 or its verified successor | Own the security assessment; do not treat it as transport authorization |
| Outbound URL/address/DNS/peer/redirect/proxy/TLS/resource authorization | EgressWeave released/versioned port or ACL | Consume; do not reimplement |
| Browser acquisition, anti-bot challenge handling, session strategy, CAPTCHA/challenge completion | Independent anti-bot owner, currently incubated by the Veilpick proposal | Do not own or source-copy |
| Ontology-guided acquisition planning and extracted-result acceptance | Veilpick | Do not turn a Wardnet allow/deny into goal completion or source truth |

Inbound bot-risk detection remains legitimate Wardnet security work. It is not an outbound challenge-solving implementation and must not be relabeled as one.

The anti-bot owner must remain independently versioned and releasable. Wardnet must not depend on mutable sibling source, a PR head, a shared database, or cross-service SQL. If Wardnet consumes anti-bot evidence, it does so through a released/versioned contract and an anti-corruption layer that preserves the producer's subject, scope, lifecycle, and provenance.

### 2. Security evidence does not become another owner's authority

Wardnet may publish or consume narrowly scoped evidence, but a consumer must not infer stronger meaning than the record proves. In particular:

- an ingress SQL-injection finding or abusive client-IP event is not evidence that a destination website is malicious;
- an IP/CIDR observation remains IP/prefix-scoped and does not establish the reputation of every virtual host on that address;
- source severity remains source severity rather than a calibrated probability;
- missing confidence remains unspecified rather than guessed;
- TTL without an authoritative observation or validity anchor is `InsufficientProvenance`; if retained for audit, the record is explicitly non-decision-bearing and cannot be treated as a current observation;
- revocation, deletion, supersession, validity, producer/version identity, tenant scope, and distribution restrictions must survive translation.

Any provider-adapter hop carrying tenant-scoped or security-sensitive evidence requires authenticated encrypted transport. Authentication and transport confidentiality are separate requirements; neither substitutes for the other. No secret, raw credential, or unnecessary tenant identifier may be copied into evidence solely for transport convenience.

Wardnet-side evidence adapters must not fetch arbitrary producer URLs to fill missing metadata. If an owning integration genuinely requires network retrieval, it must use the released EgressWeave authorization boundary, including destination policy, resolved IPv4/IPv6 validation, redirect and DNS re-resolution checks, proxy/TLS controls, and resource limits. If that owner contract is unavailable or cannot prove those controls, retrieval fails closed rather than falling back to a local HTTP implementation.

### 3. Compose policy without decision laundering

A successful anti-bot acquisition is not a security allow. A CAPTCHA, 403, or 429 is not proof that a destination is malicious. Likewise, a Wardnet reputation decision is not proof that an HTTP connection was actually blocked. The protected outbound path composes the responsible authorities without allowing one owner's `allow` to override another owner's `deny`.

Wardnet does not export a human-approval requirement into the anti-bot critical path. Conversely, autonomous browser acquisition cannot bypass Wardnet admission/security policy or EgressWeave transport authorization. Unsupported, unavailable, expired, or unverifiable required evidence is handled according to the owning fail-closed policy instead of being silently promoted to success.

## Alternatives considered

1. **Put anti-bot acquisition inside Wardnet.** Rejected because browser/session/challenge state has different invariants, failure modes, release cadence, and operational risk from gateway/SOC security policy.
2. **Make Wardnet a shared implementation library for anti-bot.** Rejected because that would couple releases and encourage ownership leakage through `waf-ids-core`.
3. **Move site reputation out with anti-bot.** Superseded by the later Wardnet product decision in PR #173: site maliciousness and SOC reputation evidence are Wardnet security responsibilities, while transport authorization stays with EgressWeave.
4. **Independent anti-bot owner with versioned evidence integration.** Selected because it preserves autonomous acquisition while keeping Wardnet and EgressWeave security authorities explicit.

## Delivery and acceptance

This ADR changes no runtime behavior. A future Wardnet integration with the anti-bot owner must demonstrate exact released producer/consumer versions, authenticated encrypted transport, provenance-preserving fixtures, lifecycle replay/expiry tests, tenant isolation, secret minimization, outage behavior, and a zero-network-fallback test proving that missing EgressWeave authority cannot trigger ad hoc HTTP retrieval.

The detailed site-reputation design, threat-evidence semantics, deployment coverage, and false-positive evaluation belong to PR #173 or its verified successor. This PR does not edit `docs/product-technical-gap-baseline.md`, which remains single-writer work in PR #130, and it does not modify workflows, branch protection, credentials, runtime source, or foreign-owner repositories.

## Consequences

Wardnet remains accountable for security admission, site maliciousness/reputation policy, and SOC evidence without absorbing browser automation. The anti-bot owner can evolve browser/challenge mechanics independently. EgressWeave remains the transport-authorization authority. The cost is explicit versioned integration and honest unavailable/unknown states instead of convenient in-process coupling.

## References

OASIS Open. (2021). *STIX Version 2.1*. https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html — Used for producer/version, validity, revocation, marking, and confidence semantics; it does not define Wardnet's reputation algorithm.

Lebo, T., Sahoo, S., & McGuinness, D. (Eds.). (2013, April 30). *PROV-O: The PROV ontology*. W3C. https://www.w3.org/TR/2013/REC-prov-o-20130430/ — Used to distinguish attribution/derivation from truth or authorization.

Parnas, D. L. (1972). On the criteria to be used in decomposing systems into modules. *Communications of the ACM, 15*(12), 1053–1058. https://doi.org/10.1145/361598.361623 — Supports decomposing around information-hiding decisions rather than implementation language; here the browser/challenge mechanism and gateway/SOC security authority change for different reasons.

Guo, C., Pleiss, G., Sun, Y., & Weinberger, K. Q. (2017). On calibration of modern neural networks. *Proceedings of Machine Learning Research, 70*, 1321–1330. https://proceedings.mlr.press/v70/guo17a.html — Supports keeping source severity/confidence distinct from calibrated probability claims.

No third-party paper PDF is redistributed by this ADR because edition-specific redistribution permission was not established. Citation and summary are sufficient for this documentation-only boundary.