# Outbound Site Reputation: product and technical design

**Status:** Proposed; documentation only. **Date:** 2026-09-05.
**Decision:** [ADR](../../adr/2026-09-05-outbound-site-reputation-engine.md).
**Delivery:** [implementation plan](../plans/2026-09-05-outbound-site-reputation.md).
**Sources:** [research register](../../papers/outbound-site-reputation-sources.md).

## 1. Product responsibility and baseline

Prevent internal users, services, automation, and agents from contacting external destinations with adverse security reputation, while giving operators an explainable reason and a controlled process for legitimate unknown destinations. The product question is: **may this workload contact this destination for this purpose now?** It is not whether a website is popular, credible, easy to scrape, or friendly to bots.

At `main@5829a0f08d78de464dd24393ce5d0f25fba9d126`, Wardnet has a configured-upstream gateway, threat imports, an IP-oriented DNSBL export, request scoring, and SOC events. It does not yet implement this outbound contract or intercept all company traffic. `ThreatIndicator` carries value/type/severity/source/TTL; `SecurityEvent` carries a client IP, route, action, score, and path. Neither is sufficient evidence for the proposed versioned destination decision. The existing inbound `score_request` and its `BLOCK_SCORE` remain unchanged.

Initial scope is domain, observable URL, and address security intelligence for HTTP(S) egress. Consumers include employee applications and internal API/LLM/tool workloads, but no application-specific scraping logic belongs in the engine. Full forward-proxy deployment, TLS interception, generic DLP, active crawling, and sandbox execution are not silently included in this first capability.

## 2. Owners and proposed components

| Owner/component | Responsibility | Explicit exclusion |
| --- | --- | --- |
| Proposed `crates/wardnet-reputation-core/` | Pure Rust evidence eligibility, canonical-subject matching, policy evaluation, explainable result | HTTP, DNS resolution, async runtime, environment, database, LLM |
| Proposed `src/reputation/` | Authenticated use cases, source adapters, immutable snapshots, policy administration, SOC projection | A second transport-policy implementation or copied sibling code |
| EgressWeave released port | URL/address authority, DNS/peer binding, redirects, proxy/TLS/trust, connection/resource limits | Wardnet maliciousness or business-exception authority |
| Controlled policy enforcement point (PEP) | Bind authenticated request to both decisions, prevent unauthorized connect/send, report actual outcome | Caller-supplied allow headers or unchecked secondary connections |
| Existing canonical supporting owners | Runtime configuration, durable storage/outbox, optional sandbox and orchestration | Reimplementation inside reputation modules |

These are proposed paths, not existing files. Keep the existing `waf-ids-core` name and public behavior; the rename and other foundation PRs are separate work. Wardnet remains independently deployable. Versioned public contracts, not cross-service SQL or mutable source checkouts, connect bounded contexts.

## 3. Admission and connection flow

```text
Authenticated workload -> controlled PEP -> Wardnet local reputation assessment
                                      -> EgressWeave transport/peer authorization
                       -> validate matching, fresh authorities and reserve audit
                       -> connect/send through owner-approved execution boundary
                       -> record enforcement outcome and SOC correlation
Reviewed intelligence -> bounded import -> validated atomic evidence snapshot
Reviewed policy/exception -> immutable policy revision -> cache invalidation
```

For a **protect** profile:

```text
permit = authenticated_context
      AND wardnet_action_is_allow
      AND egress_transport_is_allow
      AND same_target_context_and_current_authorities
      AND required_audit_reservation_succeeded
```

The diagram is a logical composition, not permission for unchecked DNS between evaluation and connect. Domain and observable-URL evidence can be checked before resolution; address evidence must be checked against each actual candidate peer before it can be used. The released integration must support an authorize-and-connect operation or an equivalently strong peer-bound execution contract. A preflight URL check followed by an ordinary independent HTTP client is unacceptable.

Bind evaluation and execution to tenant, authenticated workload, purpose, operation nonce, canonical target/profile, policy revision, evidence generation, transport-contract version, connection peer where applicable, and expiry. The PEP must verify authenticity, audience and binding of out-of-process receipts; a digest alone does not authenticate a receipt. Missing or unsupported contract versions, replay, target substitution, or peer mismatch deny protected traffic.

Re-evaluate every redirect and retry that changes connection or authority. Connection pooling and HTTP/2 coalescing must not grant a different origin prior approval. Credentials are never forwarded to a new origin merely because the first hop was allowed. Source changes invalidate positive caches. Initial protected tunnel leases are bounded to 60 seconds; renewal rechecks both authorities. A deployment must terminate newly denied active leases within that bound or report that persistent-flow protection is unsupported. The bound is a proposed requirement, not a measured capability.

## 4. Destination and evidence contracts

### Destination identity

`DestinationContextV1` contains `direction=outbound`, authenticated tenant/workload, registered purpose, operation ID, observation capabilities, and a canonical target descriptor. The descriptor distinguishes exact host, exact observable URL, and actual address/port. It includes scheme/port where relevant, canonicalization profile/version, and connection-binding evidence when available.

EgressWeave remains authoritative for executable outbound URL, address, and DNS interpretation. Wardnet matches its canonical descriptors; feed mappers must demonstrate compatible representation using released codecs or conformance vectors. Offline core tests can consume fixed canonical fixtures before that release. They must not become an independent network-authorizing parser.

Host matching uses exact names or explicitly granted dot-boundary subdomain scope. No substring matching, implicit registrable-domain widening, or public-suffix wildcard is allowed. Shared hosting/CDN address matches do not automatically condemn every hosted domain. An actual peer-address threat may deny that connection without rewriting host reputation. CNAME observations preserve alias and source scope rather than collapsing distinct authorities.

URL matching retains path case and relevant query semantics; log minimization is a separate operation. No double decoding or query stripping to manufacture a different matching identity. Credentials/fragments and ambiguous executable targets are handled by the transport owner. Only visible URL components may support URL-level assessment. IPv4/IPv6 aliases must use the same owner-approved identity; disagreement is an integration error, not permission to retry through another parser.

### Evidence and source eligibility

`EvidenceRecordV1` carries source ID, producer record ID/version, original source family, subject and explicit scope, security category, producer severity and optional confidence, observed/received times, validity interval, revocation/deletion/admission state, tenant/marking restrictions, licensing reference, and provenance references. Missing confidence remains unspecified, not zero risk or full confidence. Confidence and severity are not calibrated probabilities [R3].

`SourcePolicyV1` records allowed purposes/tenants, permitted observable kinds, whether that source may contribute to enforcement, required health/freshness, maximum evidence age, supported lifecycle grammar, polling limits, license and credential references. An authenticated transport plus a body hash is provenance evidence; the hash alone is not proof of producer authenticity.

Initially consume reviewed operator evidence and proven STIX/MISP/OpenCTI or source-specific feeds [R3, R5, R6]. Each adapter retains original semantics. Existing lossy `ThreatIndicator` rows are not automatically promoted: ambiguous history remains non-authoritative until validated original evidence or a reviewed replacement is available. MISP adapters require affirmative recognized `to_ids` and active attribute/enclosing-object lifecycle; the open #167/#170 repairs are not assumed shipped. CVE/KEV membership alone is not a site-maliciousness assertion.

Only supported indicator grammars become enforcement material. Unsupported patterns, conflicting lifecycle fields, malformed validity, or unauthorized source scope cannot be guessed into an active indicator. Preserve diagnostic counts without logging hostile payloads.

## 5. Freshness, snapshots, and cache behavior

Compute eligibility at evaluation time from producer validity and source-policy age limits. Received/import time must not replace last-observed validity. Reimport, conditional HTTP 304, retry, and process restart never rejuvenate expired evidence. Source-poll freshness and individual IOC validity are separate facts.

Validate a complete, bounded source result before atomically publishing a new generation. Full-snapshot replacement requires verified completeness, including pagination. Delta feeds require a consistent cursor and explicit tombstones; absence from a delta is not withdrawal. A successful authenticated empty snapshot differs from an empty body caused by failure. Keep only still-valid last-known-good evidence on refresh failure, without extending TTL. Older source versions cannot resurrect withdrawals; STIX revoked-object semantics remain source-faithful [R3].

Reads use immutable snapshots. Publish/invalidate atomically and retain revision identities for replay. No provider request, DNS lookup, crawler, or LLM runs inside the pure evaluation path. Evidence eligibility and tenant markings are checked again after a cache hit.

Decision-cache keys include tenant, workload, purpose, direction, full canonical target and observation scope, policy revision, evidence generation, contract/profile versions, and applicable peer binding. Expiry is the minimum of policy/exception/evidence/lease validity. Required-source expiry invalidates authorization even without a new generation. Both new threats and legitimate delisting must propagate; never retain an allow or denial indefinitely. Cache cardinality is bounded, not controlled by arbitrary host labels.

## 6. Deterministic reputation and policy

Keep three distinct dimensions:

- Assessment: `known_malicious`, `suspicious`, or `unknown`.
- Evidence health: `fresh`, `degraded`, `expired`, or `unavailable`, evaluated against required sources.
- Policy result: `allow` or `deny`, with stable reason codes; monitor produces a separate shadow result.

A current eligible match from a reviewed enforcement-capable source can establish `known_malicious`. Non-enforcement evidence may establish `suspicious`; no active eligible match means `unknown`, not safe. Dedupe syndicated feeds by source lineage. Do not add duplicate severities or invent a weighted score. Domain age, registration novelty, geography, popularity, anti-bot behavior, and isolated HTTP failures are not hard-deny evidence.

| Protect-mode condition, in precedence order | Result |
| --- | --- |
| Invalid identity/contract/binding, unmet visibility, or unavailable required authority | Deny; explain authority/visibility failure, not invented maliciousness |
| Explicit non-overridable policy deny or eligible hard-threat match | Deny, even with a business allow |
| Required evidence expired/unavailable | Deny; a business exception cannot conceal missing authority |
| Suspicious evidence | Deny in the initial protect profile; analyst review does not auto-clear it |
| Unknown with valid exact-scope business authorization and healthy required evidence | Allow subject to transport and audit gates |
| Unknown without that authorization | Deny with `unknown_destination` |

A policy declares its nonempty required-source set and acceptable maximum ages; new protect configuration is invalid without them. Optional-source failure may report `degraded` without violating required-source health. Threat-deny and transport-deny cannot be overridden by normal exceptions.

A business authorization binds exact origin, tenant, workload, purpose, approver, ticket/reason, and validity. No global wildcard. Changes use optimistic concurrency and an audit record; expiry/revocation invalidates cached decisions. An exception changes authorization, not assessment. Malware-research access belongs to a separately authorized isolated workflow, outside the ordinary protect profile.

Monitor mode records `would_allow`/`would_deny` and `enforced=false`; it does not issue a protect authorization. Existing controls still apply, but monitored traffic is explicitly not claimed reputation-protected. Mode changes and rollback are reviewed policy changes, not hidden runtime fail-open switches.

## 7. Proposed service and audit surfaces

These routes do not exist on the baseline:

| Proposed surface | Contract |
| --- | --- |
| `POST /api/v1/egress/reputation/evaluate` | Authenticated service evaluation; bounded input; immutable decision envelope |
| `GET /api/v1/egress/reputation/sources` | Source health, policy eligibility and freshness; no credentials |
| `GET/PUT /api/v1/egress/reputation/policies/{id}` | Tenant-scoped read/admin mutation with revision/If-Match |
| `POST/DELETE /api/v1/egress/reputation/exceptions/{id}` | Expiring exact-scope business authorization and revocation |
| `GET /api/v1/egress/reputation/decisions/{id}` | Authorized explanation with marking-aware evidence visibility |

Authenticate service identity through a deployment-approved workload identity/mTLS boundary; derive tenant/workload from verified identity, never trust caller JSON claims. Evaluation credentials cannot administer sources, policy, or exceptions. Operators use reader, analyst, or policy-admin capabilities; analysis does not imply policy-write permission. Runtime configuration and secrets come from the canonical registry, not new raw environment reads.

`DecisionEnvelopeV1` contains schema/version, evaluation ID, target/context binding, assessment, policy action/reasons, freshness, evaluation/expiry times, policy/evidence identities, bounded evidence references, and observation scope. Any grant artifact is authenticated and audience-bound by the service adapter, not manufactured by the pure core. A successful HTTP 200 may contain **deny**; consumers must validate the envelope, not the status alone. Invalid input/version is 400; unauthorized is 401/403; overload is 429; unavailable evaluation is 503. All error paths return no grant.

Create a separate versioned `OutboundReputationEventV1` with requester and destination distinct, decision ID, revisions, evidence references, and PEP outcome. Do not store the destination in legacy `client_ip` or project a fabricated WAF score. Link a minimized summary into existing SOC events; delivery uses the canonical durable outbox boundary, not a new network exporter.

For protect-mode allow, reserve a durable audit slot before payload release. An unavailable/full audit path denies with `audit_unavailable`; do not claim durability from an in-memory queue. Retain detailed evidence under configurable tenant retention and deletion policies. Never log raw query strings, bodies, Authorization/Cookie values, or provider credentials. Sensitive host/URL evidence is restricted; ordinary telemetry uses opaque identifiers and low-cardinality reason labels. External providers receive no per-request URLs in v1.

## 8. Interception and visibility acceptance

Company-wide claims require network enforcement: enrolled traffic must traverse the PEP, and alternative direct exits must be restricted and tested. A service SDK is sufficient only for that controlled workload, not the whole organization. Protected DNS can complement the design [R4], but existing IP DNSBL export is not domain RPZ enforcement.

For opaque HTTPS CONNECT, only the observed host/port and peer are assessed. Do not claim path-level inspection. A profile requiring full URL evidence denies insufficient visibility or requires an independently approved inspection/enrolled-client architecture. ECH, unauthorized encrypted DNS, QUIC, direct IP access, external proxies, and alternate network paths must be blocked by the deployment boundary or explicitly marked outside coverage. This PR does not assert those controls already exist.

## 9. Limits, verification, and rollout

Initial proposed limits are a 64 KiB evaluation envelope, an 8 KiB observable URL, 32 returned evidence references, and 100,000 cache entries per instance. Source imports have separately configured compressed/decompressed byte and record limits. Explanation truncation reports the total match count; it must never truncate the security decision itself. Bound candidate peers, source work, and deadlines under the released owner contract. Rejection is preferable to partial authorization.

Performance acceptance is future measured evidence: on a documented 4-vCPU/8-GiB test host, one million synthetic indicators and 1,000 evaluations/second should meet local-core p99 <= 5 ms, with all snapshot/cache memory measured. This is a proposed benchmark gate, not a current performance claim. DNS/transport/provider costs are reported separately. No production enablement based solely on a microbenchmark.

Required hostile cases and task commands are in the plan. Measure false-positive rate on a reviewed benign corpus, detection on a labeled malicious corpus, unknown rate, required-source availability, revision propagation, and actual enforced coverage. Hold out time/source-family cohorts to reduce evaluation leakage [R1, R2]. IOC match rate is not global detection recall; shadow denials are not prevented connections.

Roll out offline replay, monitor, a small protect canary, then approved workload cohorts. Require zero upstream hits for deterministic deny cases, reviewed false-positive handling, outage/recovery drills, bounded active-flow revocation, and bypass-path tests before expanding. Roll back to a compatible reviewed policy and transport release without resurrecting withdrawn intelligence or disabling existing security controls. Keep feature capability disabled by default until the applicable deployment gates pass.
