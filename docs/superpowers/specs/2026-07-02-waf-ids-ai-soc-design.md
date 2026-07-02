# WAF IDS AI SOC Design

## Objective

Build a Rust-first WAF/IDS/AI SOC gateway MVP for ContextualWisdomLab that is web-manageable, can act as an API gateway, can ingest or publish threat data, and can expose DNSBL-compatible outputs.

## Scope

The initial scope is an executable MVP, not a production SIEM replacement. It must prove the control loop: manage routes and indicators, score requests, record events, expose KPIs, and export DNSBL zone records.

## Architecture

The service is a single Rust binary using Axum. It exposes an embedded admin console, JSON management APIs, a gateway path, and DNSBL zone export. Runtime state is in memory for the MVP. The code keeps integration boundaries explicit so Coraza/OWASP CRS, Suricata, STIX/TAXII, MISP/OpenCTI, Hickory DNS, and AI SOC approval flows can be added without pretending they already exist.

## Requirements

- Bind to localhost by default.
- Support optional `ADMIN_TOKEN` for write APIs.
- Use route-scoped monitor/block modes.
- Score requests from threat indicators and DNSBL client IP matches.
- Export IPv4 DNSBL records using reversed-octet names and `A`/`TXT` records.
- Provide SOC KPI counts through JSON.
- Include CI, tests, security policy, and governance baseline files.
- Do not use Figma Code Connect.

## Non-Goals

- No custom full WAF rule engine in the MVP.
- No fake Suricata/OpenCTI/MISP integration.
- No unauthenticated remote admin deployment guidance.
- No AI-driven automatic blocking without human approval.

## Testing

Unit tests cover DNSBL name reversal, zone export, threat scoring, DNSBL scoring, route selection, and upstream URL construction. CI runs `cargo fmt --check` and `cargo test --locked`.
