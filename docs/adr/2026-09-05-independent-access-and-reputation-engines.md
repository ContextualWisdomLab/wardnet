# ADR 2026-09-05: Keep outbound anti-bot and site reputation engines outside Wardnet

- Status: Proposed; documentation-only, pending PR review
- Date: 2026-09-05
- Inspected Wardnet base: `5829a0f08d78de464dd24393ce5d0f25fba9d126`
- Consumer proposal: [Veilpick PR #3](https://github.com/ContextualWisdomLab/Veilpick/pull/3), stacked on its product ADR PR #1
- Detailed contracts: [Veilpick design at the proposal commit](https://github.com/ContextualWisdomLab/Veilpick/blob/4d0f1e55d7e88d88d29fd6279467cefde3fde1b3/docs/design/access-and-reputation-engines.md)

## Context

Wardnet is the Rust-first WAF/IDS/AI SOC/gateway owner described in [AGENTS](../../AGENTS.md), [CLAUDE](../../CLAUDE.md) and the [architecture](../architecture.md). Its core contains route enforcement, request scoring, threat indicators, DNSBL entries, event retention and feed-related state. Rust implementation language does not make these concepts equivalent to an outbound acquisition engine or a general source-reputation model.

At the inspected revision, `ThreatIndicator` in [the core](../../crates/waf-ids-core/src/lib.rs) contains `value`, `indicator_type`, `severity`, `source` and `ttl_seconds`; `DnsblEntry` identifies an address or prefix. The row alone does not establish a destination URL, original observation time, producer confidence, revocation/version lineage or source credibility. Other feed state must be evaluated explicitly where available, not assumed from these fields.

Veilpick's product contract requires ontology-guided, autonomous acquisition, first-class stealth and functioning automatic challenge resolution for supported classes. Importing gateway enforcement or SOC approval workflows into that execution path would assign the wrong owner and could introduce hidden human dependencies.

## Decision

### 1. Preserve the owner boundary

| Capability | Proposed owner | Wardnet responsibility |
| --- | --- | --- |
| Inbound request inspection and gateway enforcement | Wardnet plus proven security-engine integrations | Retain WAF/IDS/SOC/APIM behavior and existing governance |
| Outbound anti-bot access and challenge handling | Independent `anti-bot-core` / `anti-bot-engine`, initially incubated in Veilpick | Do not own browser sessions, stealth strategies, CAPTCHA solving or acquisition completion |
| Evidence-based site reputation | Independent `site-reputation-core` / `site-reputation-engine`, initially incubated in Veilpick | Optional source of correctly scoped threat observations, not the assessment authority |
| Governed destination/TLS/HTTP/browser/presentation and runtime evidence | OriginWeave through verified integration adapters | Do not fork these capabilities into the new engines |
| Ontology planning and extracted-result acceptance | Veilpick | Do not turn a gateway allow/block decision into goal completion or source truth |

Here, anti-bot is explicitly the **outbound access and challenge** meaning from the acquisition product. This decision does not prohibit Wardnet from legitimately using inbound bot-risk signals in its own gateway protection. Those signals still cannot be relabeled as a destination's reputation or an outbound solver decision.

The two new cores must not depend on `waf-ids-core` or each other. Initial repository co-location in Veilpick does not merge their domain ownership: independent schemas, release versions, standalone entry points and consumer compatibility tests are required. No existing Wardnet code is moved or copied by this proposal.

### 2. Permit evidence reuse, not decision laundering

The consumer-owned optional provider adapter may accept an authenticated, versioned `ThreatObservationV1` envelope only when its provenance and subject are sufficient. That proposed contract is not a shipped Wardnet endpoint or a claim that existing APIs already supply every field.

The envelope distinguishes typed URL/origin/host/IP subject and exact scope; original producer/record/version; genuine observation time versus collection time; validity and separately labeled consumer freshness; source severity versus optional confidence; revocation; derivation; tenant/visibility and distribution restrictions. Complete details live in the linked consumer specification, not a competing Wardnet schema definition.

| Existing input or condition | Required adapter behavior |
| --- | --- |
| Generic SQL-injection signature or gateway client-IP incident | Not a destination-site observation; reject that mapping |
| IP or CIDR DNSBL record | Preserve IP/prefix scope; do not infer every co-hosted publisher is malicious |
| TTL without an authoritative observation/validity anchor | Return `InsufficientProvenance` or retain explicitly incomplete evidence; do not manufacture a fresh observation time |
| Threat severity | Preserve as source severity, never a calibrated probability or global site score |
| Missing producer confidence | Keep unspecified, not zero and not a guessed value |
| Revoked or superseded source record | Preserve lifecycle/version semantics; no old-record replay may restore it |
| Wardnet unavailable or missing coverage | Report unavailable/unknown coverage; consumer standalone operation must remain possible |

An adapter that needs original source metadata may use a separately governed original-provider contract. It must not silently fetch arbitrary URLs or private addresses, access Wardnet's database, or recover secrets from telemetry. Unknown or unsupported mappings must be visible to the consumer. Optional sanitized exports remain subject to source sharing restrictions and tenant isolation.

STIX 2.1 distinguishes producer confidence, object versioning/revocation and indicator validity [1]. Our consumer requires explicit freshness/coverage handling and tombstones, but does not claim that STIX specifies the reputation algorithm. Provenance vocabulary is useful for attribution and derivation, not proof of truth [2]. Model confidence also needs independent calibration before being represented as a probability [3].

### 3. Keep independent policy and failure semantics

A reputable or easily accessible site is not a network permission grant. A site presenting CAPTCHA, 403 or 429 is not thereby malicious or unreliable. The anti-bot engine honors task/origin/account quotas and independently verifies challenge resolution. Its successful automated path has zero human interventions; an error or unattended stop is not successful collection.

Site reputation separates security, source reliability, access friction and coverage/freshness. Wardnet's `BLOCK_SCORE`, route block thresholds and monitor/block disposition must not become that engine's model, probability threshold or authorization result. Neither engine requires a synchronous Wardnet call on its critical path.

No new Wardnet human approval gate is exported into Veilpick. Conversely, Veilpick autonomy cannot bypass Wardnet's own security or review controls. Component policies are composed without treating one owner's metadata as another owner's authority.

## Alternatives considered

1. **Use `waf-ids-core` as the shared engine:** rejected because threat/request/enforcement models have different subjects, state and acceptance semantics.
2. **Add an all-purpose anti-bot/reputation module to Wardnet:** rejected because it expands WAF/IDS/SOC responsibility and couples unrelated releases and availability.
3. **Discard all Wardnet reuse:** rejected; properly scoped, provenance-preserving observations can be useful through an optional adapter.
4. **Independent engines with evidence-only integration:** proposed because it preserves ownership, standalone operability and explicit compatibility requirements.

## Delivery, compatibility and acceptance

Veilpick PR #3 contains ADR 0004/0005, product/technical design, separate implementation plans, proposed contracts and acceptance scenarios. It is a design-only, parent-dependent proposal, not an integrated or functioning engine. Its package/service names are proposed, not current releases. This Wardnet ADR introduces no executable, endpoint, dependency or new security detection.

A future adapter PR must show source-record fixtures, exact producer/consumer schema versions, omitted-field behavior, lifecycle replay/expiry tests, scope isolation, no secret leakage, and outage independence. It must demonstrate that a CAPTCHA-only observation cannot lower source reliability and that an ingress finding cannot masquerade as a destination finding. Run normal Wardnet Cargo/security gates if Wardnet code changes; documentation validation alone is not runtime acceptance.

Keep existing runtime/feed/security work and the sole product-gap-baseline writer in PR #130 independent. Do not edit `docs/product-technical-gap-baseline.md` or change workflows, branch protection, required checks, code-owner policy or credentials as part of this proposal. No merge, self-approval or release is performed.

## Consequences

Wardnet stays focused and can evolve security adapters without owning browser automation or editorial reliability. Consumers gain explicit evidence limitations rather than a misleading repurposed score. The cost is adapter/schema compatibility work and potentially unavailable observations until source metadata is sufficient. A missing optional provider is recorded honestly, never silently converted into a safe-site result.

## References

[1] OASIS Open. (2021). *STIX Version 2.1*, sections 3.2, 3.6 and 4.7. [Official standard](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html).

[2] Lebo, T., Sahoo, S., & McGuinness, D. (Eds.). (2013, April 30). *PROV-O: The PROV ontology*. W3C. [Dated recommendation](https://www.w3.org/TR/2013/REC-prov-o-20130430/).

[3] Guo, C., Pleiss, G., Sun, Y., & Weinberger, K. Q. (2017). On calibration of modern neural networks. *PMLR, 70*, 1321-1330. [Publisher record](https://proceedings.mlr.press/v70/guo17a.html); [arXiv:1706.04599](https://arxiv.org/abs/1706.04599).

The [consumer research record](https://github.com/ContextualWisdomLab/Veilpick/blob/4d0f1e55d7e88d88d29fd6279467cefde3fde1b3/docs/research/access-and-reputation-evidence.md) supplies eight numbered standard/academic sources and exact repository observations. These references justify semantic distinctions, not measured engine effectiveness. Paper PDFs are not redistributed: edition-specific permission has not been established, so this change cites and summarizes instead.
