# WAF IDS AI SOC

Rust-first gateway and SOC control-plane baseline for ContextualWisdomLab.

The project starts small on purpose:

- web-managed API gateway routes
- request scoring from threat indicators and DNSBL entries
- monitor/block enforcement modes
- RFC 5782-style DNSBL zone export
- SOC event and KPI APIs
- optional JSON state persistence for standalone operation
- embedded admin console

It does not pretend to be a full WAF, IDS, SIEM, or SOAR yet. Production WAF and IDS coverage should come from adapters to proven engines such as OWASP CRS/Coraza and Suricata.

## Completion Baseline

The program-complete baseline means the binary can run by itself, keep operator-managed routes/threats/DNSBL entries/events across restart when `WAF_IDS_STATE_PATH` is configured, enforce monitor/block decisions, export DNSBL records, and prove that loop through `scripts/smoke.sh`.

It is still not a hardened internet-facing deployment. Use TLS, identity-aware access, upstream allowlists, and route rollback procedures before production traffic.

## Run

```bash
cargo run
```

Open `http://127.0.0.1:8080/admin`.

Useful environment variables:

- `BIND_ADDR`: listen address, default `127.0.0.1:8080`
- `ADMIN_TOKEN`: optional write token for `POST /api/routes`, `POST /api/threats`, and `POST /api/dnsbl` via `X-Admin-Token`
- `WAF_IDS_STATE_PATH`: optional JSON state path. When omitted, the service runs with seeded in-memory state.
- `DNSBL_ORIGIN`: DNSBL zone origin, default `dnsbl.local`
- `EVENT_LIMIT`: retained event count, default `1000`; must be greater than zero

Example with persistent local state:

```bash
ADMIN_TOKEN=dev-secret \
WAF_IDS_STATE_PATH=./waf-ids-state.local.json \
DNSBL_ORIGIN=dnsbl.example \
cargo run
```

## API

```bash
curl http://127.0.0.1:8080/healthz
curl http://127.0.0.1:8080/api/routes
curl http://127.0.0.1:8080/api/threats
curl http://127.0.0.1:8080/api/dnsbl
curl http://127.0.0.1:8080/dnsbl/zone
curl http://127.0.0.1:8080/gateway/demo?q=union%20select
```

Add a blocking route:

```bash
curl -X POST http://127.0.0.1:8080/api/routes \
  -H 'content-type: application/json' \
  -H 'x-admin-token: dev-secret' \
  -d '{
    "id": "api",
    "path_prefix": "/api",
    "upstream": "https://example.com",
    "mode": "block",
    "enabled": true
  }'
```

Management writes are upserts:

- routes are keyed by `id`
- threat indicators are keyed by `indicator_type`, `value`, and `source`
- DNSBL entries are keyed by `address`

DNSBL response codes must be IPv4 loopback-style values in `127.0.0.0/8`.

## Roadmap

1. Coraza/OWASP CRS adapter for HTTP transaction scoring.
2. Suricata EVE JSON ingest and correlation with gateway events.
3. STIX/TAXII and MISP/OpenCTI feed import jobs.
4. Authoritative DNSBL service mode using Hickory DNS.
5. AI SOC analyst assist with human approval gates for blocking changes.

## Verification

```bash
cargo fmt --check
cargo test --locked
cargo clippy --locked -- -D warnings
scripts/smoke.sh
```
