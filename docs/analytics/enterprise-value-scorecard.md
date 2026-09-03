# Enterprise Value Scorecard

## Purpose

This scorecard turns the 2B KRW sale-readiness target into measurable product evidence. It is not revenue recognition, a compliance certificate, or a guarantee of production security.

## Primary KPIs

| KPI | Target for buyer lab | Evidence source |
| --- | --- | --- |
| Sale readiness pass rate | 100% of readiness checks pass | `GET /api/commercial/readiness` |
| Buyer lab time-to-value | Under 30 minutes from deploy to support bundle | deploy docs, smoke script, support bundle |
| Threat feed freshness SLA | Active feeds within configured TTL | `/api/threat-feeds/freshness`, `/api/kpis` |
| Gateway decision latency | p95 below buyer-defined edge budget | future latency histogram |
| False-positive rollback rate | Tracked and reviewed before block rollout | operations runbook and future analyst disposition |
| Support bundle completeness | Health, KPIs, license, readiness, and counts present | `GET /api/support-bundle` |
| SOC export availability | Events export as one JSON object per line | `GET /api/events.ndjson` |

## Driver Metrics

- enabled route count by mode
- imported feed count and latest update time
- fresh and stale imported feed counts
- threat indicator count by source and severity
- DNSBL entry count by response code, source, and TTL
- blocked and monitored events by route
- coverage, smoke, CI, Scorecard, and release evidence status
- buyer evidence document completeness

## Guardrails

- unauthorized management write attempts
- persistence failures during management writes or event writes
- p95 and p99 gateway decision latency
- upstream proxy error rate
- stale feed percentage
- score override and block rollback count
- AI recommendation approval rate before enforcement changes

## Current Runtime Coverage

The current runtime exposes the count-based subset through `/api/kpis`, `/api/commercial/readiness`, `/api/threat-feeds`, `/api/threat-feeds/freshness`, `/api/events.ndjson`, `/api/support-bundle`, and `/dnsbl/zone`. Latency, false-positive, override, and analyst-disposition metrics require follow-on telemetry and workflow storage.
