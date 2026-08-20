# Wardnet Product–Technical Gap Baseline

- **Baseline date:** 2026-08-20
- **Scope:** buyer-visible product, security, observability, interoperability, operability, and release gaps
- **Rule:** a gap is closed only when the production implementation, exact-head tests/checks, documentation, and operational evidence agree.

## Current buyer-facing baseline

Wardnet is a Rust-first WAF/IDS/AI-SOC gateway with bounded security-event retention and an administrative product surface. PR #90 adds a portable security-event interoperability boundary rather than embedding a specific SIEM vendor SDK in the enforcement path.

## Gap register

| Gap | Buyer impact | Current state | Closure evidence | Priority |
|---|---|---|---|---|
| SIEM-neutral event schema | SOC teams otherwise need a custom parser before onboarding Wardnet | PR #90 implements OCSF 1.8.0 Detection Finding JSONL | exact-head OCSF contract tests + CI/SAST/Security/Fuzz | P0 |
| OpenTelemetry log export | Enterprise collectors cannot correlate Wardnet decisions with distributed traces | PR #90 implements OTLP/HTTP JSON logs with OTLP-defined hex trace/span IDs | exact-head OTLP wire-contract tests + collector integration rehearsal | P0 |
| RFC 5424 syslog interoperability | Existing SOC relays cannot ingest a standards-based stream | PR #90 implements RFC 5424 with source-derived timestamp, bounded `meta.sequenceId`, registered structured data, and UTF-8 JSON message | RFC timestamp/sequence boundary tests + relay rehearsal | P0 |
| Export secret safety | Security evidence can accidentally leak credentials/query secrets | PR #90 allowlists fields, strips path query/fragment data, normalizes controls, and redacts common equals/colon credential forms | contract + property + fuzz tests | P0 |
| Parser robustness | Malformed or hostile NDJSON can cause partial or inconsistent exports | PR #90 parser is bounded, fail-closed, order/duplicate checked, and extracted for property/fuzz testing | stable proptest + cargo-fuzz + no-partial-output tests | P0 |
| Durable SIEM delivery | A process crash or downstream outage can lose acknowledgement state | Not closed; tracked by #81 | PostgreSQL authority + transactional outbox + retry/dead-letter + receipt/replay tests | P0 |
| In-process OpenTelemetry traces | Operators cannot follow ingress → policy → storage → integration latency and failures | Not closed; tracked by #85 | trace propagation across HTTP/policy/storage/workers/integrations with sampling/privacy contract | P0 |
| Runtime metrics and SLOs | Buyers cannot operate Wardnet against availability/latency/error objectives | Not closed; tracked by #85 | OTel metrics, SLI definitions, SLO dashboards/alerts, load-test evidence | P0 |
| Collector authentication and transport policy | Portable payloads still need secure production delivery | Deliberately outside exporter; receiving collector owns credentials | mTLS/TLS deployment profile, secret rotation, destination allowlist, failure runbook | P0 |
| Vendor-specific SIEM acceptance | OCSF/syslog compatibility does not prove Splunk/Sentinel/Elastic onboarding | Not closed | tested index/parser packs, dashboards/detections, documented supported versions | P1 |
| Security-event retention/replay contract | Small retained event window can break delayed downstream consumers | Partially available; durable replay not proven | retention sizing, cursor/outbox replay, backpressure and recovery benchmarks | P0 |
| Observability data governance | Security telemetry contains IPs and potentially regulated identifiers | Export minimizes fields but receiving-system policy remains external | retention/access/purpose controls, audit evidence, CSAP/SOC 2 control mapping | P0 |

## PR #90 architecture decision

The exporter remains a deterministic Rust protocol boundary with no destination credential, retry policy, or arbitrary network egress. This preserves enforcement-path latency and makes downstream integrations replaceable. OCSF, OTLP/HTTP JSON, and RFC 5424 all originate from the same normalized event contract.

## Next development loop

1. Finish PR #90 review findings and exact-head checks, then merge without bypassing protection.
2. Implement #81 transactional outbox and downstream receipt/replay semantics.
3. Implement #85 in-process OpenTelemetry traces, metrics, SLI/SLO definitions, and collector integration tests.
4. Add buyer-lab profiles for at least one OCSF-native security lake and one RFC 5424/OTLP collector path.
5. Re-run the gap register after each merge and add newly discovered buyer-visible gaps before declaring release readiness.

## Release gate

Wardnet must not claim production SIEM/OpenTelemetry readiness until portable event contracts, durable delivery, secure collector handoff, runtime traces/metrics, replay/recovery, and buyer-facing integration evidence all pass on the exact release head.
