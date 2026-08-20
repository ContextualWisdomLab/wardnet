# SIEM and OpenTelemetry standards traceability

## Product decisions and evidence

| External source | Product decision | Implementation | Verification |
|---|---|---|---|
| OCSF 1.8.0 categories, Detection Finding, Finding, Metadata, and Security Control profile | Represent retained Wardnet security decisions as Detection Finding `2004`, activity `Create`, with the Security Control profile. Preserve Wardnet-only fields under `unmapped.wardnet`. | `src/bin/wardnet-event-exporter.rs` | `ocsf_detection_finding_is_versioned_allowlisted_and_redacted` |
| OTLP specification 1.11.0 | Emit OTLP/HTTP JSON with lower-camel-case fields, hexadecimal trace/span IDs, numeric enum values, and decimal-string 64-bit integer fields. | `src/bin/wardnet-event-exporter.rs` | `otlp_json_filters_checkpoint_and_preserves_trace_context` |
| OpenTelemetry Logs Data Model | Map source time, observed time, severity number/text, body, event name, resource, scope, attributes, and optional trace context. | `src/bin/wardnet-event-exporter.rs` | OTLP contract test and runbook collector example |
| OpenTelemetry trace context in non-OTLP logs | Use `trace_id`, `span_id`, and `trace_flags`; place them in the RFC 5424 `OpenTelemetry` structured-data element. | `src/bin/wardnet-event-exporter.rs` | `rfc5424_uses_structured_data_and_single_line_messages` |
| RFC 5424 | Produce VERSION 1 syslog with a valid priority, header, structured data, escaped parameter values, and one physical output line per event. | `src/bin/wardnet-event-exporter.rs` | RFC 5424 contract test |
| W3C Trace Context 1.1 | Require a non-zero 16-byte trace ID and non-zero 8-byte parent/span ID encoded as hexadecimal, with optional one-byte flags. | `src/bin/wardnet-event-exporter.rs` | `incomplete_or_invalid_trace_context_is_rejected` |
| NIST SP 800-92 | Keep security logging useful for incident investigation while applying explicit collection, protection, retention, and review responsibilities. | ADR and runbook | Receiving-system ownership and data-minimization sections |

## Version policy

- **OCSF is pinned to 1.8.0.** A newer OCSF release requires a mapping review, updated fixture assertions, and a changelog entry. Output metadata always declares the selected schema version.
- **OTLP is implemented against specification 1.11.0.** OTLP/JSON compatibility is wire-contract compatibility; this exporter does not claim to be an OpenTelemetry SDK.
- **OpenTelemetry semantic conventions are not copied wholesale.** Stable resource and log fields are used where their meanings match. Wardnet-specific fields use the `wardnet.*` namespace.
- **RFC 5424 uses no invented Private Enterprise Number.** The `wardnet` SD-ID is unqualified until ContextualWisdomLab owns an IANA PEN.
- **Vendor certification is not implied.** Splunk, Elastic, Microsoft Sentinel, Datadog, and other integrations must be tested and documented independently when a real buyer environment is available.

## APA 7th references

Gerhards, R. (2009). *The syslog protocol* (RFC 5424). Internet Engineering Task Force. https://doi.org/10.17487/RFC5424

Kent, K., & Souppaya, M. (2006). *Guide to computer security log management* (NIST Special Publication 800-92). National Institute of Standards and Technology. https://doi.org/10.6028/NIST.SP.800-92

Open Cybersecurity Schema Framework Project. (2026). *Open Cybersecurity Schema Framework schema, version 1.8.0*. https://github.com/ocsf/ocsf-schema/tree/1.8.0

OpenTelemetry Authors. (2026). *OpenTelemetry protocol specification, version 1.11.0*. https://opentelemetry.io/docs/specs/otlp/

OpenTelemetry Authors. (2026). *OpenTelemetry logs data model*. https://opentelemetry.io/docs/specs/otel/logs/data-model/

OpenTelemetry Authors. (2026). *Trace context in non-OTLP log formats*. https://opentelemetry.io/docs/specs/otel/compatibility/logging_trace_context/

OpenTelemetry Authors. (2026). *OpenTelemetry specification, version 1.60.0*. https://opentelemetry.io/docs/specs/otel/

World Wide Web Consortium. (2021). *Trace Context: Level 1* (2nd ed.). https://www.w3.org/TR/trace-context/
