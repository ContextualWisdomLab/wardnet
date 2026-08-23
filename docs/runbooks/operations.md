# Operations Runbook

## Local Persistent Run

```bash
ADMIN_TOKEN=dev-secret \
WAF_IDS_STATE_PATH=./waf-ids-state.local.json \
DNSBL_ORIGIN=dnsbl.local \
EVENT_LIMIT=1000 \
cargo run
```

Open `http://127.0.0.1:8080/admin`.

### Admin secrets (credential registry)

Secret-bearing admin tokens are loaded into a process-local **credential registry**
at bootstrap. Runtime auth reads from that registry — not by re-reading the env
on each request.

| Bootstrap transport | Variable / path | Notes |
| --- | --- | --- |
| Env (dev / CI) | `ADMIN_TOKEN`, `ADMIN_TOKENS` | Still supported; seeds the registry only |
| Credentials file (preferred for lab/prod packaging) | `WAF_IDS_CREDENTIALS_PATH` | JSON object with `admin_token` and/or `admin_tokens` keys; file values win per key over env |

Example credentials file:

```json
{
  "admin_token": "replace-me",
  "admin_tokens": "ops-token:ops:admin,audit-token:auditor:readonly"
}
```

`ADMIN_TOKENS` / `admin_tokens` items are `token`, `token:actor`, or
`token:actor:role`. Roles:

| Role labels | Capability |
| --- | --- |
| `admin`, `write`, `writer`, `operator` (default) | Management writes + audit-log read |
| `readonly`, `read`, `reader`, `ro` | Audit-log read only (no policy mutation) |

`GET /api/audit-logs` requires a valid admin credential when auth is configured
(readonly tokens work). Write APIs still require a write-capable principal.
Token values never appear in audit log payloads.

```bash
WAF_IDS_CREDENTIALS_PATH=./credentials.local.json \
WAF_IDS_STATE_PATH=./waf-ids-state.local.json \
cargo run
```

Health reports `credentials_source` (`file` / `env` / `none`) and
`admin_auth_configured` (boolean) without exposing secret values.

## Health Check

```bash
curl -fsS http://127.0.0.1:8080/healthz
```

Expected fields:

- `status`: `ok`
- `persistence`: `memory` or `file`
- `dnsbl_origin`: configured DNSBL origin without a trailing dot
- `event_limit`: retained security event count
- `credentials_source`: `file`, `env`, or `none`
- `admin_auth_configured`: whether any admin write token is configured
- `backup`: `ready` on PostgreSQL (logical export/restore available) or `disabled` on file/memory
- `event_partitions`: HASH child count for `security_event` (8 on PostgreSQL, 0 on file/memory)

## Control-plane backup and restore drill

PostgreSQL mode (`/healthz.persistence=postgres`) is the only authority that
can export or restore. File/memory adapters report `/healthz.backup=disabled`.

Declared RPO: last successful `GET /api/backup`. Declared RTO: 60 seconds for
the isolated drill.

```bash
# Export a hashed tenant snapshot (admin read token). Client IPs and paths stay unmasked.
curl -fsS -H "X-Admin-Token: $ADMIN_TOKEN" http://127.0.0.1:8080/api/backup > backup.json

# Isolated restore drill (does not replace the live tenant).
curl -fsS -H "X-Admin-Token: $ADMIN_TOKEN" -X POST http://127.0.0.1:8080/api/backup/drill

# Restore the live tenant from an artifact (admin write). Schema and payload-hash
# mismatches fail closed. The action is audited.
curl -fsS -H "X-Admin-Token: $ADMIN_TOKEN" -H 'content-type: application/json' \
  -d @backup.json -X POST http://127.0.0.1:8080/api/backup
```

The artifact does not contain admin tokens or `CONTROL_PLANE_DATABASE_URL`.
Physical/PITR backups remain a DBA concern; this is the application-level
recovery path with tenant RLS preserved.

## Smoke Test

```bash
scripts/smoke.sh
```

The smoke test starts the service on a temporary port with a temporary JSON state file, verifies admin and management surfaces, creates a blocking route, registers a commercial license, imports a threat feed, triggers a blocked gateway request, checks KPIs, readiness, support bundle, and DNSBL export, restarts the process, and verifies that route/license/feed data persisted.

When `WAF_IDS_STATE_PATH` is enabled, the process writes a temporary sibling file and atomically replaces the configured state path. If a management write cannot be persisted, the in-memory mutation is rolled back and the API returns `500`.

## Safe Change Procedure

1. Start new routes in `monitor` mode.
2. Confirm recent events and KPIs show expected matches.
3. Switch only the specific route to `block` mode.
4. Keep the previous route JSON available for rollback.
5. Disable the route or switch back to `monitor` if legitimate traffic is blocked.

## Commercial Readiness Procedure

1. Register buyer-approved license metadata through `POST /api/commercial/license`.
2. Import reviewed threat feed data through `POST /api/threat-feeds/import`.
3. Trigger at least one gateway event in monitor or block mode.
4. Check `GET /api/commercial/readiness`.
5. Export `GET /api/support-bundle` for buyer lab evidence or support handoff.

## Production Boundaries

This baseline is suitable for local and controlled lab deployments. Internet-facing use still requires:

- TLS termination and identity-aware admin access
- upstream allowlists and egress controls
- durable database storage with backups (PostgreSQL logical export at `GET /api/backup`; isolated restore drill at `POST /api/backup/drill`; declared RPO is last successful export, declared RTO is 60s)
- SSO/OIDC federation (multi-token RBAC with readonly role and audit-log auth are available)
- asynchronous event persistence or a database-backed event store for high-throughput gateway traffic
- Detection-quality corpora and Suricata EVE tail/shipper remain open. In-process libcoraza (`CORAZA_LIB_PATH` + `CORAZA_RULES_PATH` or `CORAZA_DIRECTIVES`) evaluates each live `/gateway` transaction; otherwise HTTP sidecar consult at `CORAZA_WAF_URL`. Audit ingest at `POST /api/waf/coraza/audit` still fuses block hits into DNSBL/`client_ip` indicators. Set `PROVEN_ENGINE_FAIL_CLOSED=true` in production so an engine outage does not silently allow traffic.
- Live Suricata EVE tailing / shipper (HTTP ingest of EVE alerts is available at `POST /api/ids/suricata/eve`)
- Live MISP REST pull or live OpenCTI GraphQL pull (HTTP STIX/MISP/OpenCTI document ingest and TAXII 2.1 poll are available at `POST /api/threat-intel/stix`, `POST /api/threat-intel/misp`, `POST /api/threat-intel/opencti`, and `POST /api/threat-intel/taxii/poll`)
- human approval workflow for AI SOC recommendations that change enforcement
