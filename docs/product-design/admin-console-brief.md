# Product Design Brief

## Audience

Security operators and platform engineers who need to understand what the gateway is protecting, why traffic was blocked or monitored, and whether threat intelligence is fresh enough to trust.

## Primary Surfaces

1. **Threat Overview**: live blocks, monitored detections, high-severity indicators, stale feeds.
2. **Gateway Routes**: route prefix, upstream, mode, enabled status, last event.
3. **WAF Rules**: future Coraza/OWASP CRS rule packs, anomaly threshold, exclusions.
4. **IDS Events**: future Suricata event stream grouped by client, route, and signature.
5. **DNSBL Zones**: listed IPs, response codes, TTL, reason, source, zone export status.
6. **AI Triage**: event summaries, recommended action, confidence, approval status.
7. **Incident Timeline**: correlated gateway, IDS, DNSBL, and threat-intel changes.
8. **Feed Health**: source freshness, import errors, indicator volume, rollback controls.

## MVP UI Direction

Use a dense operational console rather than a landing page. The first viewport should show route state, threat indicators, DNSBL entries, KPIs, recent events, and zone export.

## Figma Constraint

Figma Code Connect is intentionally not used. Figma work should be limited to FigJam architecture diagrams and editable UI mockups generated from the product brief or captured admin console.
