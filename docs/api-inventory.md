# Wardnet HTTP API inventory

Snapshot: 2026-08-26, `origin/main` at `107117634764c901dff540044585d64088fafedb`.

| Product area | Existing HTTP contracts | Lifecycle gap after this change |
| --- | --- | --- |
| Health and deployment | `GET /healthz`, `/readyz`, `/api/version`, `/metrics`, `/api/support-bundle` | No authenticated runtime configuration view or reload contract. |
| Gateway and routes | `ANY /gateway/{path}`, `GET/POST /api/routes`, `GET/PUT/DELETE /api/routes/{route_id}`, `POST /api/evaluate` | Route collection pagination and an explicit gateway decision trace lookup remain absent. |
| WAF | `POST /api/waf/coraza/audit` | No rule-set activation/version API; this must follow the Coraza/CRS authority contract rather than inventing rules. |
| IDS | `POST /api/ids/suricata/eve` | No sensor registration, sensor health, or EVE cursor/checkpoint API. |
| AI SOC | `GET /api/soc/llm-config`, `POST /api/soc/analyze` | No analysis job/history/feedback lifecycle. |
| Events and KPIs | `GET /api/events`, `/api/events.ndjson`, `/api/kpis`, `/api/audit-logs` | Event and audit cursor pagination, time ranges, acknowledgement/case state, and retention controls remain absent. |
| DNSBL | `GET/POST /api/dnsbl`, `GET/PUT/DELETE /api/dnsbl/{address}`, `GET /dnsbl/zone` | Serial/conditional zone transfer contracts remain absent. |
| Threat intelligence | `GET /api/threats`, `GET /api/threat-feeds`, `/freshness`; import endpoints for generic feeds, phishing-database, STIX, MISP, TAXII, and OpenCTI | Individual indicator/feed lifecycle and import idempotency keys remain absent. |
| APIM and load balancing | Route CRUD and prefix-based upstream proxying | No upstream pool/member, health-check, retry/circuit-breaker, API consumer, quota, or API-key lifecycle. These need persisted models before endpoints. |
| Credentials and config | Admin token RBAC; integration config status views | No credential registry CRUD/rotation metadata API. Secret values must never be returned. Operational config still lacks a durable KV model. |
| Durability and audit | JSON snapshot persistence and mutation audit rows | No immutable remote audit sink, tenant boundary, or general optimistic-concurrency revision. Route items now use ETag/If-Match. |

## Route resource contract

Legacy `POST /api/routes` remains an upsert and keeps its existing response shape/status.
New clients should use the item resource:

- `GET /api/routes/{route_id}` returns the route and an `ETag` header.
- `PUT /api/routes/{route_id}` creates a missing route. Replacing an existing route requires
  `If-Match` with the latest ETag (`428` when absent, `412` when stale).
- `DELETE /api/routes/{route_id}` requires `If-Match` and returns `204`.
- Writes require a write-capable admin principal. An authenticated read-only principal gets
  `403`; a missing or invalid credential gets `401`. Successful replace/delete operations are
  persisted and audited.

The machine-readable contract is [openapi.yaml](openapi.yaml).

## DNSBL resource contract

- `GET /api/dnsbl/{address}` returns one IPv4 or IPv6 entry and an `ETag` header.
- `PUT /api/dnsbl/{address}` creates a missing entry. Replacing an existing entry requires
  `If-Match`; the path and body addresses must match.
- `DELETE /api/dnsbl/{address}` requires `If-Match` and returns `204`.
- Writes use the same write-capable admin, persistence, rollback, and audit contract as routes.
