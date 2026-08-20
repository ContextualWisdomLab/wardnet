# Changelog

All notable changes to Wardnet are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project intends to use [Semantic Versioning](https://semver.org/spec/v2.0.0.html) when release automation is established.

## [Unreleased]

### Added

- `wardnet-event-exporter`, a bounded Rust command that transforms `/api/events.ndjson` into:
  - OCSF 1.8.0 Detection Finding JSONL;
  - OTLP/HTTP JSON `ExportLogsServiceRequest` payloads;
  - RFC 5424 syslog records with OpenTelemetry trace context.
- Checkpoint filtering through `--after-id`.
- Standards traceability, architecture decision, and operator runbook for SIEM/OpenTelemetry handoff.
- End-to-end tests covering OCSF classification, OTLP resource/log structure, trace propagation, RFC 5424 framing, malformed-input atomicity, and CLI rejection paths.

### Security

- Added an explicit export allowlist instead of forwarding arbitrary source properties.
- Added bounded batch, line, event-count, and rendered-output limits.
- Added fail-closed rejection for malformed events, duplicate IDs, invalid timestamps, and malformed trace context.
- Added query/fragment removal, control-character normalization, and credential-shaped value redaction before external export.
