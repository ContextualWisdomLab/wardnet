# Wardnet

[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/ContextualWisdomLab/wardnet)

**Rust-first gateway and SOC control plane for governed traffic policy, threat evidence, DNSBL operations, and security-operations handoff.**

Wardnet gives an operator one bounded place to manage gateway routes, threat indicators, DNSBL entries, enforcement mode, SOC events, feed freshness, and buyer/support evidence. It is deliberately small enough to run standalone while keeping room for proven external WAF, IDS, SIEM, and orchestration engines behind explicit adapters.

It is **not** presented as a complete internet-edge WAF, IDS, SIEM, or SOAR. The current source is an operational baseline and evidence surface; production-grade detection coverage remains a separate integration and hardening responsibility.

## What Wardnet provides

| Operator need | Current Wardnet responsibility |
| --- | --- |
| Gateway policy | Manage enabled routes and monitor/block mode through the control-plane API |
| Threat evidence | Store operator-reviewed indicators and DNSBL entries with source/TTL context |
| Request decisions | Score requests from the currently configured local threat evidence and apply route mode |
| DNSBL operations | Export RFC 5782-style loopback response codes and a DNSBL zone view |
| SOC evidence | Retain bounded security events, KPI snapshots, freshness state, and NDJSON event export |
| Support handoff | Produce health/readiness/evidence support bundles without returning administrator secrets |
| Buyer diligence | Expose bounded commercial/readiness/evidence reports without turning them into certification or transaction authority |
| Standalone durability | Optionally persist operator-managed state to a local JSON state file |

## Current maturity

The current source package metadata is `0.1.0`, but **this repository has no published GitHub release yet**. A source version, buyer-readiness endpoint, successful smoke test, or open pull request is not release or production evidence.

Wardnet can run locally, persist its current state model, enforce its current monitor/block decisions, expose an embedded admin console, and produce operational evidence. It is not yet a hardened public-edge deployment. Before real production traffic, operators still need a reviewed TLS/identity boundary, externally managed credentials, upstream/destination policy, rollback/recovery controls, and the required proven-engine integrations for the intended detection scope.

## Product boundary

Wardnet owns the **gateway and SOC control-plane boundary** represented by this repository: route policy, current local threat/DNSBL evidence, request scoring/enforcement mode, operational evidence, support handoff, and bounded management APIs.

Adjacent systems remain independently authoritative:

- proven WAF rule engines such as Coraza/OWASP CRS own their detection semantics when integrated;
- IDS/network telemetry engines such as Suricata own their packet/event detection semantics when integrated;
- external SIEM/OpenTelemetry destinations own downstream retention and investigation;
- threat-intelligence providers own their source datasets and terms;
- `ContextualWisdomLab/contextual-orchestrator` owns model/provider routing for any model-assisted SOC workflow; and
- customer identity, TLS termination, secrets, deployment policy, and network topology remain deployment authorities rather than README assumptions.

A threat score or buyer-readiness report is evidence produced by Wardnet, not authorization to make unrelated infrastructure changes.

## Quick start

Wardnet is a Rust workspace. From a source checkout:

```bash
cargo run
```

The default listener is loopback-only. Open:

```text
http://127.0.0.1:8080/admin
```

Check liveness:

```bash
curl -fsS http://127.0.0.1:8080/healthz
```

### Add local persistence

Current protected-source configuration uses `WAF_IDS_STATE_PATH` for the optional state file:

```bash
ADMIN_TOKEN='replace-with-a-local-admin-secret' \
WAF_IDS_STATE_PATH=./wardnet-state.local.json \
DNSBL_ORIGIN=dnsbl.example \
cargo run
```

`ADMIN_TOKEN` protects management writes through `X-Admin-Token`. The current baseline permits a credential-free local development mode; do not interpret that convenience as a safe public-bind configuration.

Useful current settings:

| Setting | Purpose |
| --- | --- |
| `BIND_ADDR` | Listener address; defaults to `127.0.0.1:8080` |
| `ADMIN_TOKEN` | Optional management-write token for the current baseline |
| `WAF_IDS_STATE_PATH` | Optional JSON persistence path |
| `DNSBL_ORIGIN` | DNSBL zone origin; defaults to `dnsbl.local` |
| `EVENT_LIMIT` | Retained event bound; must be greater than zero |

## Core operator API

A few read surfaces are enough to understand the running control plane:

```bash
curl -fsS http://127.0.0.1:8080/api/routes
curl -fsS http://127.0.0.1:8080/api/threats
curl -fsS http://127.0.0.1:8080/api/dnsbl
curl -fsS http://127.0.0.1:8080/api/threat-feeds/freshness
curl -fsS http://127.0.0.1:8080/api/events.ndjson
curl -fsS http://127.0.0.1:8080/api/support-bundle
```

Management writes use the configured administrator boundary. For example, a local route can be added with:

```bash
curl -X POST http://127.0.0.1:8080/api/routes \
  -H 'content-type: application/json' \
  -H 'x-admin-token: replace-with-a-local-admin-secret' \
  -d '{
    "id": "api",
    "path_prefix": "/api",
    "upstream": "https://example.com",
    "mode": "block",
    "enabled": true
  }'
```

Management writes use stable domain keys: routes by route identity, threat indicators by indicator type/value/source, and DNSBL entries by address. DNSBL response codes are constrained to IPv4 loopback-style values in `127.0.0.0/8`.

For threat-feed ingestion, use only reviewed sources whose commercial terms and redistribution/use boundaries are acceptable for the deployment. Feed freshness and import success do not change the upstream provider's license or data-usage terms.

## Buyer and support evidence

Wardnet exposes bounded reporting surfaces that help a pilot operator or buyer inspect the current runtime:

| Evidence | Endpoint |
| --- | --- |
| Commercial metadata | `GET /api/commercial/license` |
| Readiness checks and blockers | `GET /api/commercial/readiness` |
| Evidence inventory | `GET /api/commercial/evidence-manifest` |
| Threat-feed freshness | `GET /api/threat-feeds/freshness` |
| SOC event export | `GET /api/events.ndjson` |
| Support handoff | `GET /api/support-bundle` |

These endpoints may report incomplete or blocked states. They are not a compliance certification, deployment approval, customer commitment, valuation, legal opinion, or completed transaction. The detailed diligence contract lives in [`docs/commercial/buyer-due-diligence.md`](docs/commercial/buyer-due-diligence.md).

## Architecture at a glance

```text
Client traffic
     |
     v
+-------------------------------+
|            Wardnet            |
| gateway + SOC control plane   |
|-------------------------------|
| route policy                  |
| threat / DNSBL evidence       |
| monitor / block decision      |
| events / KPI / freshness      |
| admin + support evidence      |
+---------------+---------------+
                |
        explicit adapters
                |
      +---------+---------+
      |                   |
      v                   v
 proven WAF / IDS     SIEM / SOC tools
 engines              and operators
```

The current core remains one Rust workspace because the reusable domain crate does not yet have an independent release cadence or external consumer contract. Repository boundaries should change only when those product/reuse responsibilities genuinely diverge.

See [`docs/architecture.md`](docs/architecture.md) for the detailed component and trust boundaries.

## Deployment

The repository currently ships source deployment assets for local/container and Kubernetes evaluation:

- [`Dockerfile`](Dockerfile)
- [`deploy/docker-compose.yml`](deploy/docker-compose.yml)
- [`deploy/kubernetes/wardnet.yaml`](deploy/kubernetes/wardnet.yaml)

The Kubernetes filename above is the canonical repository path on this branch. Renaming the source path does not rename live Kubernetes objects; stateful resource-identity migration is a separate operator concern.

For production-oriented setup and rollback expectations, read [`docs/deployment/production.md`](docs/deployment/production.md) before exposing the service beyond loopback.

## Security posture

The current baseline is designed to fail explicitly on malformed managed state and bounded input, but source-level controls do not replace deployment security. In particular:

- keep management access behind a reviewed identity/credential boundary;
- do not commit administrator credentials, provider keys, customer traffic, or private threat data;
- validate upstream and threat-feed destinations before enabling remote network access;
- preserve source attribution and terms for imported intelligence;
- keep a rollback path for route and enforcement changes; and
- treat model-assisted SOC output as advisory until an authorized operator acts on it.

Security-sensitive parsers and scoring/state boundaries are exercised through property tests and coverage-guided fuzzing; see [`docs/fuzzing.md`](docs/fuzzing.md).

## Verify the source

Use the locked workspace and strict compiler/lint path:

```bash
cargo fmt --check
cargo test --locked --workspace
cargo clippy --locked --workspace --all-targets -- -D warnings
scripts/smoke.sh
```

A passing source suite is engineering evidence for that exact revision. It is not proof of a live deployment, third-party feed availability, external detection-engine coverage, or release publication.

## Documentation map

- [`docs/architecture.md`](docs/architecture.md) — component, domain, and trust boundaries.
- [`docs/adr/`](docs/adr/) — architecture decisions.
- [`docs/deployment/production.md`](docs/deployment/production.md) — production-oriented deployment and rollback guidance.
- [`docs/runbooks/`](docs/runbooks/) — operator procedures.
- [`docs/commercial/buyer-due-diligence.md`](docs/commercial/buyer-due-diligence.md) — buyer evidence and claim boundaries.
- [`docs/fuzzing.md`](docs/fuzzing.md) — hostile-input/property/fuzz verification.
- [`docs/doctoring/`](docs/doctoring/) — research and standards traceability.

## Contributing

Keep changes inside Wardnet's gateway/SOC control-plane responsibility. Do not copy a proven security engine, model router, external intelligence provider, or sibling product into this repository merely to avoid an integration boundary. Public behavior, security-sensitive parsing, persistence, and deployment-contract changes should update tests and operator documentation together.

Before opening a change, run the source verification commands above and keep customer-facing claims tied to current protected-source behavior rather than planned PRs.

## License

Wardnet source is licensed under the [MIT License](LICENSE). Third-party crates, threat-intelligence sources, external rule engines, datasets, and deployment components retain their own terms and are not relicensed by this repository.
