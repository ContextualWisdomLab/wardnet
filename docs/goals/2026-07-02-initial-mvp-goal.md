# Initial MVP Goal

## Goal

Create and publish a concrete ContextualWisdomLab WAF/IDS/AI SOC project MVP that proves the core loop:

1. operators can manage gateway routes, threat indicators, and DNSBL entries through a web surface;
2. the gateway can score requests and enforce monitor/block decisions;
3. security events feed SOC KPIs;
4. DNSBL data can be exported in an RFC 5782-compatible DNS zone shape;
5. the repo has CI, tests, security policy, and documented next integration points.

## Acceptance Criteria

- Repository exists under `ContextualWisdomLab/waf-ids-ai-soc`.
- `cargo test` passes locally and in CI.
- `cargo fmt --check` passes locally and in CI.
- `GET /admin` renders a management console.
- `GET /api/routes`, `/api/threats`, `/api/dnsbl`, `/api/events`, and `/api/kpis` return structured JSON.
- `POST /api/routes`, `/api/threats`, and `/api/dnsbl` update runtime state and support `ADMIN_TOKEN`.
- `GET /gateway/{path}` performs route selection, request scoring, event recording, and block/monitor behavior.
- `GET /dnsbl/zone` exports IPv4 DNSBL records as reversed-octet `A` and `TXT` records.
- Docs explicitly mark Coraza/OWASP CRS, Suricata, STIX/TAXII, MISP/OpenCTI, Hickory DNS authoritative serving, and AI SOC approval flow as follow-up adapters.
