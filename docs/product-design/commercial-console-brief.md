# Commercial Console Product Brief

## Objective

Make the admin console useful for a buyer-facing pilot without turning it into a marketing page. Operators should see route health, feed freshness, DNSBL posture, license status, and blockers in one scan.

## Primary Views

- Routes: route id, prefix, mode, enabled state, upstream, last event count.
- Threat Feeds: feed id, source, last update, TTL, imported indicator count.
- DNSBL: entry count, origin, recent sources, zone export link.
- Commercial Readiness: pass/fail checks, blockers, target value, support bundle link.
- Support Bundle: generated timestamp, health, KPIs, evidence counts, license metadata.

## Interaction Rules

- Dangerous writes require explicit operator token configuration.
- New routes default to monitor mode.
- Blockers must be specific and copyable for implementation tracking.
- License metadata must not ask operators to paste raw license secrets.
- Support bundle output must avoid admin tokens, credentials, and raw payload secrets.

## Visual Direction

Use a dense operations-console layout with compact sections, muted neutral surfaces, clear status badges, and no landing-page hero. This is a security operations tool, not a promotional site.
