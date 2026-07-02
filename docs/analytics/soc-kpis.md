# SOC KPI Model

## Primary KPIs

- **Decision Latency**: p95 gateway decision time from request received to monitor/block decision.
- **Detection Precision**: analyst-confirmed true positives divided by confirmed detections.
- **False Positive Rate**: analyst-confirmed false positives divided by total blocked requests.
- **Mean Time To Triage**: time from first event in an incident cluster to analyst disposition.
- **Feed Freshness**: percentage of active feeds updated within their expected interval.
- **DNSBL Lookup Readiness**: zone export age and authoritative DNS publication status.

## Driver Metrics

- route count by enforcement mode
- threat indicator count by source and severity
- DNSBL entry count by response code, TTL, and source
- threat feed count and last update age by feed
- blocked versus monitored events by route
- top matched indicators
- stale indicators past TTL
- feed import error count

## Guardrails

- gateway p95 and p99 latency
- upstream error rate after proxying
- block-to-allow override ratio
- AI recommendation approval rate
- policy rollback count
- management API unauthorized write attempts

## MVP Measurement

The baseline exposes `GET /api/kpis` with counts for routes, indicators, DNSBL entries, threat feeds, events, blocked events, and monitored events. Latency, precision, triage time, and full feed freshness percentages require the next telemetry and analyst-disposition work.
