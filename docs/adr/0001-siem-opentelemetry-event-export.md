# ADR 0001: SIEM and OpenTelemetry event export boundary

- **Status:** Accepted
- **Date:** 2026-08-20
- **Decision owners:** Wardnet maintainers
- **Related issues:** #81, #85, #87

## Context

Wardnet already exposes retained security decisions through `GET /api/events.ndjson` and ingests security evidence from Coraza/OWASP CRS and Suricata. The NDJSON contract is useful for buyer-lab verification, but it is not by itself a portable SIEM or observability contract.

A full SIEM is a separate product category with durable storage, search, correlation, case management, retention, access control, and incident workflow. Wardnet should not reproduce those systems. It should instead emit standards-based records that security lakes, SIEMs, log routers, and OpenTelemetry Collectors can consume.

Production delivery is also not yet a synchronous HTTP concern. Durable external effects depend on the PostgreSQL authority and transactional outbox tracked by #80 and #81.

## Decision

Add a separate Rust binary, `wardnet-event-exporter`, that consumes the existing Wardnet event NDJSON stream from standard input and emits exactly one of three contracts:

1. **OCSF 1.8.0 Detection Finding JSONL**
   - Category UID `2` (`Findings`).
   - Class UID `2004` (`Detection Finding`).
   - Activity ID `1` (`Create`) and type UID `200401`.
   - The OCSF `security_control` profile records whether Wardnet allowed, denied, or observed activity.
   - Wardnet-only source fields remain under `unmapped.wardnet`; they are not mislabeled as OCSF attributes that the selected class does not define.

2. **OTLP/HTTP JSON `ExportLogsServiceRequest`**
   - Lower-camel-case Protobuf JSON field names.
   - 64-bit nanosecond timestamps and integer attributes encoded as decimal strings.
   - Trace and span identifiers encoded as hexadecimal strings.
   - Resource attributes include `service.name`, `service.namespace`, `service.version`, and `deployment.environment.name`.
   - The payload can be posted to an OpenTelemetry Collector's `/v1/logs` endpoint with `Content-Type: application/json`.

3. **RFC 5424 syslog**
   - Facility `local0`.
   - Registered `origin` and `meta` structured-data elements carry source software, optional client IP, and event sequence ID.
   - OpenTelemetry trace context is carried in the stable `OpenTelemetry` structured-data element.
   - Wardnet-specific event fields are emitted as a UTF-8 BOM-prefixed JSON message, not as an unregistered SD-ID.
   - The RFC 5424 header timestamp is deterministically rendered from source Unix seconds as RFC 3339. `meta.sequenceId` is emitted only for event IDs in `1..=2147483647`; larger Wardnet IDs remain in the JSON message.

The exporter is a deterministic protocol boundary rather than a network daemon. Standard input and output make it composable with `curl`, OpenTelemetry Collector, Fluent Bit, Vector, syslog relays, and vendor agents without giving the exporter provider credentials or arbitrary egress authority.

## Security and privacy contract

- Read the complete bounded batch before writing output.
- Reject malformed JSON, duplicate IDs, invalid timestamps, oversized records, and incomplete or invalid trace context.
- Produce no partial output if any input line is invalid.
- Ignore unknown source fields rather than forwarding them.
- Strip query strings and fragments from paths.
- Collapse control characters so records cannot inject extra syslog lines.
- Redact credential-shaped values from exported text.
- Never export request headers, cookies, authorization values, bodies, threat-feed payloads, or runtime credentials.
- Keep client IP addresses because they are required security evidence, but classify and retain them under the receiving system's security/privacy policy.

## Consequences

### Positive

- Wardnet can integrate with vendor-neutral security schemas and observability pipelines without embedding a vendor SDK.
- Every output is reproducible from the same source event.
- OCSF and OTLP retain a stable event ID and correlation context.
- The bounded fail-closed transformation is testable without a live SIEM.

### Negative

- This decision does not create durable delivery, backpressure, retry, dead-letter, or acknowledgement semantics. Those remain in #81.
- This decision does not instrument Wardnet's HTTP, database, policy, or worker paths with live spans and metrics. Those remain in #85.
- OCSF and OpenTelemetry evolve independently; pinned mappings require explicit version upgrades and contract tests.
- Vendor-specific certification, index templates, detections, dashboards, and retention policies remain outside this repository.

## Rejected alternatives

### Vendor-specific SDKs in the gateway process

Rejected because provider credentials, retry semantics, dependency risk, and release cadence would enter the enforcement path.

### CEF as the only SIEM format

Rejected because CEF is vendor-oriented and loses structured semantics needed by OCSF and OTLP. A CEF adapter may be added later behind the same normalized event boundary when a buyer requires it.

### Treating raw NDJSON as OpenTelemetry

Rejected because OTLP has a defined Protobuf JSON envelope, timestamp encoding, resource/scope structure, severity model, and trace-context fields.

### Inventing or borrowing a private enterprise number for RFC 5424

Rejected. RFC 5424 reserves unqualified SD-IDs for IANA registration and requires locally extensible SD-IDs to use the owner's assigned IANA Private Enterprise Number. Wardnet instead uses registered `origin` and `meta` elements, the OpenTelemetry-defined trace element, and a JSON message until ContextualWisdomLab owns a PEN.
