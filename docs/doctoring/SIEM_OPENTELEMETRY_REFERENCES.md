# SIEM and OpenTelemetry standards traceability

## Product decisions and evidence

| External source | Product decision | Implementation | Verification |
|---|---|---|---|
| OCSF 1.8.0 categories, Detection Finding, Finding, Metadata, and Security Control profile | Represent retained Wardnet security decisions as Detection Finding `2004`, activity `Create`, with the Security Control profile. Preserve Wardnet-only fields under `unmapped.wardnet`. | `src/bin/wardnet-event-exporter.rs` | `ocsf_detection_finding_is_versioned_allowlisted_and_redacted` |
| OTLP specification 1.11.0 | Emit OTLP/HTTP JSON with lower-camel-case fields, hexadecimal trace/span IDs, numeric enum values, and decimal-string 64-bit integer fields. OTLP deliberately overrides ordinary ProtoJSON base64 encoding for trace/span IDs. | `src/bin/wardnet-event-exporter.rs` | `otlp_json_filters_checkpoint_and_preserves_trace_context` |
| OpenTelemetry Logs Data Model | Map source time, severity number/text, body, event name, resource, scope, attributes, and optional trace context. Do not fabricate an observed timestamp that the source event does not contain. | `src/bin/wardnet-event-exporter.rs` | OTLP contract test and runbook collector example |
| OpenTelemetry trace context in non-OTLP logs | Use `trace_id`, `span_id`, and `trace_flags`; place them in the RFC 5424 `OpenTelemetry` structured-data element. | `src/bin/wardnet-event-exporter.rs` | `rfc5424_uses_standard_structured_data_and_single_line_json_message` |
| RFC 5424 | Produce VERSION 1 syslog with source-derived RFC 3339 time, a valid priority and header, registered `origin`/`meta` elements, escaped parameter values, a BOM-prefixed UTF-8 JSON message, and one physical output line per event. Emit `meta.sequenceId` only in its registered `1..=2147483647` range. Do not use the RFC's reserved example PEN `32473` or an unregistered custom SD-ID. | `src/bin/wardnet-event-exporter.rs` | RFC 5424 timestamp and sequence-boundary contract tests |
| W3C Trace Context 1.1 | Require a non-zero 16-byte trace ID and non-zero 8-byte parent/span ID encoded as hexadecimal; accept only the currently defined sampled flag bit. | `src/bin/wardnet-event-exporter.rs` | `incomplete_or_invalid_trace_context_is_rejected`, `unsupported_trace_flags_fail_closed` |
| NIST SP 800-92 | Keep security logging useful for incident investigation while applying explicit collection, protection, retention, and review responsibilities. | ADR and runbook | Receiving-system ownership and data-minimization sections |
| Meng et al. (2019), LogAnomaly | Preserve semantic content in normalized security-event text rather than collapsing events to opaque template/index identifiers; keep normalization deterministic and evidence-preserving so downstream anomaly systems retain useful semantics. | Allowlisted OCSF/OTLP/syslog message and attributes | Redaction, path normalization, malformed-input atomicity, and event-contract tests |

## Research note

Meng et al. (2019) show that log-anomaly detection can lose useful information when log templates are reduced to numerical identifiers and demonstrate a semantic representation of unstructured logs on production datasets. Wardnet does not implement their anomaly detector in this PR. The paper supports the narrower interoperability decision to preserve sanitized event semantics and provenance when normalizing security events for downstream SIEM and observability consumers. The publisher-hosted paper is linked below; no PDF is vendored because redistribution rights were not independently established for this repository.

## Version policy

- **OCSF is pinned to 1.8.0.** A newer OCSF release requires a mapping review, updated fixture assertions, and a changelog entry. Output metadata always declares the selected schema version.
- **OTLP is implemented against specification 1.11.0.** OTLP/JSON compatibility is wire-contract compatibility; this exporter does not claim to be an OpenTelemetry SDK.
- **OpenTelemetry semantic conventions are not copied wholesale.** Stable resource and log fields are used where their meanings match. Wardnet-specific fields use the `wardnet.*` namespace.
- **RFC 5424 uses no invented Private Enterprise Number.** Unqualified custom SD-IDs are IANA-reserved, so Wardnet uses registered `origin` and `meta`, the OpenTelemetry-defined trace element, and a JSON message until ContextualWisdomLab has an assigned PEN.
- **Vendor certification is not implied.** Splunk, Elastic, Microsoft Sentinel, Datadog, and other integrations must be tested and documented independently when a real buyer environment is available.

## APA 7th references

Gerhards, R. (2009). *The syslog protocol* (RFC 5424). Internet Engineering Task Force. https://doi.org/10.17487/RFC5424

Kent, K., & Souppaya, M. (2006). *Guide to computer security log management* (NIST Special Publication 800-92). National Institute of Standards and Technology. https://doi.org/10.6028/NIST.SP.800-92

Meng, W., Liu, Y., Zhu, Y., Zhang, S., Pei, D., Liu, Y., Chen, Y., Zhang, R., Tao, S., Sun, P., & Zhou, R. (2019). LogAnomaly: Unsupervised detection of sequential and quantitative anomalies in unstructured logs. In *Proceedings of the Twenty-Eighth International Joint Conference on Artificial Intelligence* (pp. 4739–4745). International Joint Conferences on Artificial Intelligence Organization. https://doi.org/10.24963/ijcai.2019/658

Open Cybersecurity Schema Framework Project. (2026). *Open Cybersecurity Schema Framework schema, version 1.8.0*. https://github.com/ocsf/ocsf-schema/tree/1.8.0

OpenTelemetry Authors. (2026). *OpenTelemetry protocol specification, version 1.11.0*. https://opentelemetry.io/docs/specs/otlp/

OpenTelemetry Authors. (2026). *OpenTelemetry logs data model*. https://opentelemetry.io/docs/specs/otel/logs/data-model/

OpenTelemetry Authors. (2026). *Trace context in non-OTLP log formats*. https://opentelemetry.io/docs/specs/otel/compatibility/logging_trace_context/

OpenTelemetry Authors. (2026). *OpenTelemetry specification, version 1.60.0*. https://opentelemetry.io/docs/specs/otel/

World Wide Web Consortium. (2021). *Trace Context: Level 1* (2nd ed.). https://www.w3.org/TR/trace-context/
