# SIEM and OpenTelemetry export runbook

## Purpose

Use the `wardnet-event-exporter` binary to transform Wardnet's bounded security-event stream into:

- OCSF 1.8.0 Detection Finding JSONL;
- OTLP/HTTP JSON logs for an OpenTelemetry Collector;
- RFC 5424 syslog records.

The exporter is a deterministic protocol transformer. It does not own delivery retries, durable checkpoints, credentials, retention, incident cases, or SIEM indexes.

## Build

```bash
cargo build --locked --bin wardnet-event-exporter
```

Verify the command surface:

```bash
cargo run --locked --bin wardnet-event-exporter -- --help
```

## Obtain the Wardnet source stream

For a local Wardnet instance:

```bash
curl --fail --silent --show-error \
  http://127.0.0.1:8080/api/events.ndjson \
  > wardnet-events.ndjson
```

Treat the file as security-sensitive evidence because it may contain client IP addresses, routes, paths, and detection reasons. Do not place it in source control.

## OCSF 1.8.0 export

```bash
cargo run --quiet --locked --bin wardnet-event-exporter -- \
  --format ocsf \
  < wardnet-events.ndjson \
  > wardnet-ocsf.ndjson
```

Each output line is an OCSF Detection Finding (`class_uid=2004`) with the `security_control` profile. Wardnet-specific source fields remain under `unmapped.wardnet`.

Validate the output is JSONL before handing it to a security lake or SIEM forwarder:

```bash
python3 - <<'PY'
import json
from pathlib import Path

for line_number, line in enumerate(Path("wardnet-ocsf.ndjson").read_text().splitlines(), 1):
    event = json.loads(line)
    assert event["metadata"]["version"] == "1.8.0", line_number
    assert event["class_uid"] == 2004, line_number
print("OCSF JSONL contract valid")
PY
```

## OTLP/HTTP JSON export

Create one `ExportLogsServiceRequest`:

```bash
cargo run --quiet --locked --bin wardnet-event-exporter -- \
  --format otlp-json \
  --service-name wardnet-edge \
  --service-version 0.1.0 \
  --deployment-environment production \
  < wardnet-events.ndjson \
  > wardnet-logs.otlp.json
```

Post it to an OpenTelemetry Collector OTLP/HTTP logs endpoint:

```bash
curl --fail --silent --show-error \
  -H 'Content-Type: application/json' \
  --data-binary @wardnet-logs.otlp.json \
  http://127.0.0.1:4318/v1/logs
```

Use TLS and the receiving platform's secret-management mechanism outside a local lab. Do not place collector authorization headers in Wardnet event fields or command-line arguments that are visible in process listings.

## RFC 5424 syslog export

```bash
cargo run --quiet --locked --bin wardnet-event-exporter -- \
  --format rfc5424 \
  < wardnet-events.ndjson \
  > wardnet-syslog.log
```

The output is one message per line. It renders the source event time as an RFC 3339 header timestamp, uses the RFC-registered `origin` element for Wardnet software and optional client-IP metadata, emits `meta.sequenceId` only for event IDs in RFC 5424's `1..=2147483647` range, and uses the stable OpenTelemetry `OpenTelemetry` element when trace context exists. Remaining Wardnet fields, including the exact source Unix timestamp and all Wardnet event IDs, are carried in a UTF-8 BOM-prefixed JSON message. No example or unowned IANA Private Enterprise Number is claimed.

RFC 5424 does not provide confidentiality. Send these records over a protected transport such as a mutually authenticated TLS syslog relay or a collector-side file/pipe that is protected by operating-system permissions.

## Incremental checkpoints

The exporter can omit already acknowledged event IDs:

```bash
cargo run --quiet --locked --bin wardnet-event-exporter -- \
  --format ocsf \
  --after-id 4200 \
  < wardnet-events.ndjson
```

`--after-id` is a stateless filter, not a durable acknowledgement. Until #81 provides transactional outbox and receipt semantics, the caller must persist the acknowledged event ID and account for Wardnet event-retention limits.

## Failure behavior

The exporter exits non-zero and writes no output when any of the following occurs:

- input exceeds 16 MiB;
- a line exceeds 1 MiB;
- more than 100,000 events are supplied;
- the input is not UTF-8;
- any non-empty line is malformed JSON;
- an event ID is zero or duplicated;
- a timestamp cannot be represented at nanosecond precision;
- required fields are empty or oversized;
- trace and span identifiers are incomplete, malformed, or all zero;
- rendered output exceeds 64 MiB.

Investigate and correct the source batch rather than deleting the failing line. Silent row loss would break security evidence and reconciliation.

## Data minimization

The exporter forwards only the explicit Wardnet event contract. It:

- strips query strings and fragments from paths;
- removes control characters that could create injected log records;
- redacts credential-shaped tokens in exported text;
- ignores unknown input properties;
- does not export headers, cookies, request/response bodies, API keys, or threat-feed payloads.

Client IP addresses remain because SOC investigation depends on them. Apply tenant authorization, retention, legal/privacy review, and deletion restrictions in the receiving system.

## Operational ownership

| Concern | Owner |
|---|---|
| Wardnet event creation and bounded retention | Wardnet |
| Deterministic OCSF/OTLP/RFC 5424 transformation | `wardnet-event-exporter` |
| Durable delivery, retry, dead letter, acknowledgement | #81 outbox/worker boundary |
| Collector routing and vendor exporter credentials | OpenTelemetry Collector / log router |
| Search, correlation, detections, cases, retention | Receiving SIEM/security lake |
| In-process traces, metrics, SLOs, alerting | #85 |

## Verification

```bash
cargo fmt --check
cargo test --locked --workspace
cargo clippy --locked --workspace --all-targets -- -D warnings
```

The end-to-end contracts are in `tests/siem_opentelemetry_export.rs`.
