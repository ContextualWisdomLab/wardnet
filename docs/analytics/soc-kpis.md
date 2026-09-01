# SOC KPI Model

## Primary KPIs

- **Decision Latency**: p95 gateway decision time from request received to monitor/block decision.
- **Detection Precision**: analyst-confirmed true positives divided by confirmed detections.
- **False Positive Rate**: analyst-confirmed false positives divided by total blocked requests.
- **Mean Time To Triage**: time from first event in an incident cluster to analyst disposition.
- **Feed Freshness**: percentage of active feeds updated within their expected interval.
- **DNSBL Lookup Readiness**: zone export age and authoritative DNS publication status.
- **Buyer Evidence Completeness**: required sale-readiness evidence endpoints, documents, and deployment assets listed in `GET /api/commercial/evidence-manifest`.
- **Management Audit Coverage**: successful admin writes represented in `GET /api/audit-logs` without secrets.

## Driver Metrics

- route count by enforcement mode
- threat indicator count by source and severity
- DNSBL entry count by response code, TTL, and source
- threat feed count and last update age by feed
- fresh and stale feed counts
- blocked versus monitored events by route
- top matched indicators
- stale indicators past TTL
- feed import error count
- buyer evidence manifest endpoint count and missing required evidence blockers
- management audit-log count by action, resource, actor, and outcome

## Guardrails

- gateway p95 and p99 latency
- upstream error rate after proxying
- block-to-allow override ratio
- AI recommendation approval rate
- policy rollback count
- management API unauthorized write attempts
- audit-log records containing secrets or raw request bodies

## MVP Measurement

The baseline exposes `GET /api/kpis` with counts for routes, indicators, DNSBL entries, threat feeds, fresh feeds, stale feeds, events, blocked events, monitored events, and management audit logs. `GET /api/commercial/evidence-manifest` adds the buyer-facing checklist that maps those signals to required runtime endpoints, committed documents, and deployment assets. `GET /metrics` now exports those gauges plus buyer-meaningful operational readiness signals: enterprise sale readiness, readiness check pass/fail counts, gateway route readiness, and whether admin write authentication is configured. These counters and readiness gauges provide the continuous, broadly available operational signals advocated by [Sigelman et al.](https://research.google.com/pubs/pub36356.html), but they do not yet provide the request-level traces needed to diagnose latency across components. Latency, precision, triage time, and full feed freshness percentages still require the next telemetry and analyst-disposition work; in particular, [Chandola et al.](https://doi.org/10.1145/1541880.1541882) show that anomaly-detection methods have different trade-offs, so detection quality must be validated with precision and false-positive measurements rather than inferred from event volume alone.

## Research Grounding

- **Sigelman et al. (2010), [*Dapper, a Large-Scale Distributed Systems Tracing Infrastructure*](https://research.google.com/pubs/pub36356.html).** Production tracing benefits from low-overhead, ubiquitous instrumentation and continuous monitoring. This supports collecting gateway latency and readiness signals continuously, while also motivating future request-level traces for cross-component diagnosis.
- **Xu et al. (2009), [*Detecting Large-Scale System Problems by Mining Console Logs*](https://doi.org/10.1145/1629575.1629587).** Structured features derived from operational logs can expose runtime problems and produce operator-facing explanations. This grounds retaining event, feed-error, and triage signals as inputs to future anomaly detection rather than treating raw log volume as a detection result.
- **Chandola, Banerjee, and Kumar (2009), [*Anomaly Detection: A Survey*](https://doi.org/10.1145/1541880.1541882).** Anomaly-detection techniques vary by data assumptions, computational cost, and application context. This supports pairing detection counts with analyst-confirmed precision, false-positive rate, and time-to-triage guardrails.
