//! Standards-based export of Wardnet security events.
//!
//! The module deliberately consumes Wardnet's existing newline-delimited JSON
//! event contract and emits only an allowlisted subset. It does not perform
//! network delivery, durable retry, or downstream acknowledgement; those
//! responsibilities belong to a collector or the transactional outbox tracked
//! separately by the production-readiness backlog.

use serde::Deserialize;
use serde_json::{Map, Value, json};
use std::fmt::{self, Display, Formatter};
use std::io::{Read, Write};
use std::net::IpAddr;

const MAX_INPUT_BYTES: usize = 16 * 1024 * 1024;
const MAX_ACTION_CHARS: usize = 64;
const MAX_REASON_CHARS: usize = 2_048;
const MAX_ROUTE_CHARS: usize = 256;
const MAX_PATH_CHARS: usize = 2_048;
const OCSF_VERSION: &str = "1.8.0";
const OCSF_CATEGORY_UID: u64 = 2;
const OCSF_CLASS_UID: u64 = 2_004;
const OCSF_TYPE_UID: u64 = 200_401;
const OTEL_SCOPE_NAME: &str = "org.contextualwisdomlab.wardnet.security";
const OTEL_EVENT_NAME: &str = "org.contextualwisdomlab.wardnet.security.decision";
const USAGE: &str = "Usage: wardnet-event-exporter --format <ocsf|otlp-json|rfc5424> [--after-id <id>] [--service-name <name>] [--service-version <version>] [--deployment-environment <name>]\n";

/// A bounded, non-secret diagnostic returned by the exporter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportError(String);

impl ExportError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl Display for ExportError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for ExportError {}

/// Parse command-line options, validate the complete input, and write one
/// standards-compliant export without emitting partial output for bad input.
pub fn execute<I, R, W>(args: I, mut input: R, mut output: W) -> Result<(), ExportError>
where
    I: IntoIterator<Item = String>,
    R: Read,
    W: Write,
{
    let parse_result = parse_options(args)?;
    let options = match parse_result {
        ParseResult::Help => {
            output
                .write_all(USAGE.as_bytes())
                .map_err(|error| ExportError::new(format!("failed to write help: {error}")))?;
            return Ok(());
        }
        ParseResult::Run(options) => options,
    };

    let mut input_bytes = Vec::new();
    input
        .by_ref()
        .take((MAX_INPUT_BYTES + 1) as u64)
        .read_to_end(&mut input_bytes)
        .map_err(|error| ExportError::new(format!("failed to read input: {error}")))?;
    if input_bytes.len() > MAX_INPUT_BYTES {
        return Err(ExportError::new(format!(
            "input exceeds the {MAX_INPUT_BYTES}-byte limit"
        )));
    }

    let input_text = std::str::from_utf8(&input_bytes)
        .map_err(|_| ExportError::new("input must be UTF-8 NDJSON"))?;
    let events = parse_events(input_text, options.after_id)?;
    let rendered = render(&events, &options)?;

    output
        .write_all(rendered.as_bytes())
        .map_err(|error| ExportError::new(format!("failed to write output: {error}")))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutputFormat {
    Ocsf,
    OtlpJson,
    Rfc5424,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Options {
    format: OutputFormat,
    after_id: u64,
    service_name: String,
    service_version: String,
    deployment_environment: String,
}

enum ParseResult {
    Help,
    Run(Options),
}

fn parse_options<I>(args: I) -> Result<ParseResult, ExportError>
where
    I: IntoIterator<Item = String>,
{
    let mut arguments = args.into_iter();
    let mut format = None;
    let mut after_id = None;
    let mut service_name = None;
    let mut service_version = None;
    let mut deployment_environment = None;

    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--help" | "-h" => return Ok(ParseResult::Help),
            "--format" => {
                if format.is_some() {
                    return Err(ExportError::new("duplicate --format option"));
                }
                let value = required_value(&mut arguments, "--format")?;
                format = Some(match value.as_str() {
                    "ocsf" => OutputFormat::Ocsf,
                    "otlp-json" => OutputFormat::OtlpJson,
                    "rfc5424" => OutputFormat::Rfc5424,
                    _ => return Err(ExportError::new("unsupported format")),
                });
            }
            "--after-id" => {
                if after_id.is_some() {
                    return Err(ExportError::new("duplicate --after-id option"));
                }
                let value = required_value(&mut arguments, "--after-id")?;
                after_id = Some(
                    value
                        .parse::<u64>()
                        .map_err(|_| ExportError::new("--after-id must be an unsigned integer"))?,
                );
            }
            "--service-name" => {
                if service_name.is_some() {
                    return Err(ExportError::new("duplicate --service-name option"));
                }
                let value = required_value(&mut arguments, "--service-name")?;
                service_name = Some(validate_option_value(value, "--service-name", 255)?);
            }
            "--service-version" => {
                if service_version.is_some() {
                    return Err(ExportError::new("duplicate --service-version option"));
                }
                let value = required_value(&mut arguments, "--service-version")?;
                service_version = Some(validate_option_value(value, "--service-version", 128)?);
            }
            "--deployment-environment" => {
                if deployment_environment.is_some() {
                    return Err(ExportError::new(
                        "duplicate --deployment-environment option",
                    ));
                }
                let value = required_value(&mut arguments, "--deployment-environment")?;
                deployment_environment = Some(validate_option_value(
                    value,
                    "--deployment-environment",
                    128,
                )?);
            }
            _ => return Err(ExportError::new("unknown option")),
        }
    }

    let format = format.ok_or_else(|| ExportError::new("missing required --format option"))?;
    Ok(ParseResult::Run(Options {
        format,
        after_id: after_id.unwrap_or_default(),
        service_name: service_name.unwrap_or_else(|| "wardnet".to_string()),
        service_version: service_version.unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_string()),
        deployment_environment: deployment_environment
            .unwrap_or_else(|| "unspecified".to_string()),
    }))
}

fn required_value<I>(arguments: &mut I, option: &str) -> Result<String, ExportError>
where
    I: Iterator<Item = String>,
{
    arguments
        .next()
        .ok_or_else(|| ExportError::new(format!("missing value for {option}")))
}

fn validate_option_value(
    value: String,
    option: &str,
    maximum_chars: usize,
) -> Result<String, ExportError> {
    let char_count = value.chars().count();
    if value.trim().is_empty() || char_count > maximum_chars || value.chars().any(char::is_control)
    {
        return Err(ExportError::new(format!("invalid value for {option}")));
    }
    Ok(value)
}

#[derive(Debug, Deserialize)]
struct InputEvent {
    id: u64,
    timestamp_unix: u64,
    client_ip: Option<IpAddr>,
    route_id: Option<String>,
    action: String,
    reason: String,
    score: u16,
    path: String,
    #[serde(default)]
    trace_id: Option<String>,
    #[serde(default)]
    span_id: Option<String>,
    #[serde(default)]
    trace_flags: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NormalizedEvent {
    id: u64,
    timestamp_unix: u64,
    timestamp_unix_nano: String,
    client_ip: Option<String>,
    route_id: Option<String>,
    action: String,
    reason: String,
    score: u16,
    path: String,
    trace_context: Option<TraceContext>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TraceContext {
    trace_id_hex: String,
    span_id_hex: String,
    trace_flags_hex: String,
    trace_id_bytes: [u8; 16],
    span_id_bytes: [u8; 8],
    trace_flags: u8,
}

fn parse_events(input: &str, after_id: u64) -> Result<Vec<NormalizedEvent>, ExportError> {
    let mut events = Vec::new();
    for (index, line) in input.lines().enumerate() {
        let line_number = index + 1;
        if line.trim().is_empty() {
            continue;
        }
        let event: InputEvent = serde_json::from_str(line).map_err(|error| {
            ExportError::new(format!("line {line_number}: invalid JSON: {error}"))
        })?;
        let event = normalize_event(event, line_number)?;
        if event.id > after_id {
            events.push(event);
        }
    }
    Ok(events)
}

fn normalize_event(event: InputEvent, line_number: usize) -> Result<NormalizedEvent, ExportError> {
    if event.action.trim().is_empty() {
        return Err(ExportError::new(format!(
            "line {line_number}: action must not be empty"
        )));
    }

    let timestamp_unix_nano = event
        .timestamp_unix
        .checked_mul(1_000_000_000)
        .ok_or_else(|| {
            ExportError::new(format!(
                "line {line_number}: timestamp exceeds the OTLP uint64 range"
            ))
        })?
        .to_string();

    let trace_context = TraceContext::from_parts(
        event.trace_id,
        event.span_id,
        event.trace_flags,
        line_number,
    )?;

    Ok(NormalizedEvent {
        id: event.id,
        timestamp_unix: event.timestamp_unix,
        timestamp_unix_nano,
        client_ip: event.client_ip.map(|address| address.to_string()),
        route_id: event
            .route_id
            .map(|value| sanitize_text(&value, MAX_ROUTE_CHARS))
            .filter(|value| !value.is_empty()),
        action: sanitize_text(&event.action, MAX_ACTION_CHARS),
        reason: sanitize_text(&event.reason, MAX_REASON_CHARS),
        score: event.score,
        path: sanitize_path(&event.path),
        trace_context,
    })
}

impl TraceContext {
    fn from_parts(
        trace_id: Option<String>,
        span_id: Option<String>,
        trace_flags: Option<String>,
        line_number: usize,
    ) -> Result<Option<Self>, ExportError> {
        match (trace_id, span_id, trace_flags) {
            (None, None, None) => Ok(None),
            (Some(trace_id), Some(span_id), Some(trace_flags)) => {
                let trace_id_bytes = decode_hex::<16>(&trace_id).map_err(|message| {
                    ExportError::new(format!("line {line_number}: trace context {message}"))
                })?;
                let span_id_bytes = decode_hex::<8>(&span_id).map_err(|message| {
                    ExportError::new(format!("line {line_number}: trace context {message}"))
                })?;
                let trace_flags_bytes = decode_hex::<1>(&trace_flags).map_err(|message| {
                    ExportError::new(format!("line {line_number}: trace context {message}"))
                })?;
                if trace_id_bytes.iter().all(|value| *value == 0) {
                    return Err(ExportError::new(format!(
                        "line {line_number}: trace context trace_id must not be all zero"
                    )));
                }
                if span_id_bytes.iter().all(|value| *value == 0) {
                    return Err(ExportError::new(format!(
                        "line {line_number}: trace context span_id must not be all zero"
                    )));
                }
                Ok(Some(Self {
                    trace_id_hex: trace_id.to_ascii_lowercase(),
                    span_id_hex: span_id.to_ascii_lowercase(),
                    trace_flags_hex: trace_flags.to_ascii_lowercase(),
                    trace_id_bytes,
                    span_id_bytes,
                    trace_flags: trace_flags_bytes[0],
                }))
            }
            _ => Err(ExportError::new(format!(
                "line {line_number}: trace context must include trace_id, span_id, and trace_flags"
            ))),
        }
    }
}

fn decode_hex<const N: usize>(value: &str) -> Result<[u8; N], &'static str> {
    let bytes = value.as_bytes();
    if bytes.len() != N * 2 || !bytes.is_ascii() {
        return Err("has an invalid length or non-ASCII value");
    }

    let mut decoded = [0_u8; N];
    for index in 0..N {
        let high = decode_hex_digit(bytes[index * 2]).ok_or("contains a non-hex digit")?;
        let low = decode_hex_digit(bytes[index * 2 + 1]).ok_or("contains a non-hex digit")?;
        decoded[index] = (high << 4) | low;
    }
    Ok(decoded)
}

fn decode_hex_digit(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn render(events: &[NormalizedEvent], options: &Options) -> Result<String, ExportError> {
    match options.format {
        OutputFormat::Ocsf => render_ocsf(events, options),
        OutputFormat::OtlpJson => render_otlp_json(events, options),
        OutputFormat::Rfc5424 => render_rfc5424(events, options),
    }
}

fn render_ocsf(
    events: &[NormalizedEvent],
    options: &Options,
) -> Result<String, ExportError> {
    let mut output = String::new();
    for event in events {
        let severity = EventSeverity::for_event(event);
        let trace = event.trace_context.as_ref();
        let document = json!({
            "activity_id": 1,
            "activity_name": "Create",
            "category_uid": OCSF_CATEGORY_UID,
            "category_name": "Findings",
            "class_uid": OCSF_CLASS_UID,
            "class_name": "Detection Finding",
            "type_uid": OCSF_TYPE_UID,
            "type_name": "Detection Finding: Create",
            "time": event.timestamp_unix * 1_000,
            "severity_id": severity.ocsf_id(),
            "severity": severity.caption(),
            "message": event.reason,
            "status_id": 1,
            "status": "New",
            "is_alert": true,
            "confidence_score": event.score.min(100),
            "risk_score": event.score.min(100),
            "metadata": {
                "version": OCSF_VERSION,
                "uid": format!("wardnet-event-{}", event.id),
                "original_event_uid": event.id.to_string(),
                "original_time": event.timestamp_unix * 1_000,
                "log_format": "JSON",
                "log_name": "wardnet.security_events",
                "source": "Wardnet /api/events.ndjson",
                "product": {
                    "name": "Wardnet",
                    "vendor_name": "ContextualWisdomLab",
                    "version": options.service_version,
                }
            },
            "finding_info": {
                "uid": format!("wardnet-event-{}", event.id),
                "title": format!("Wardnet {} decision", event.action),
                "desc": event.reason,
                "created_time": event.timestamp_unix * 1_000,
                "types": ["WAF/IDS Detection"],
            },
            "unmapped": {
                "wardnet": {
                    "event_id": event.id,
                    "timestamp_unix": event.timestamp_unix,
                    "client_ip": event.client_ip,
                    "route_id": event.route_id,
                    "action": event.action,
                    "reason": event.reason,
                    "score": event.score,
                    "path": event.path,
                    "trace_id": trace.map(|context| context.trace_id_hex.as_str()),
                    "span_id": trace.map(|context| context.span_id_hex.as_str()),
                    "trace_flags": trace.map(|context| context.trace_flags_hex.as_str()),
                }
            }
        });
        let line = serde_json::to_string(&document)
            .map_err(|error| ExportError::new(format!("failed to encode OCSF JSON: {error}")))?;
        output.push_str(&line);
        output.push('\n');
    }
    Ok(output)
}

fn render_otlp_json(
    events: &[NormalizedEvent],
    options: &Options,
) -> Result<String, ExportError> {
    let log_records = events.iter().map(otlp_log_record).collect::<Vec<_>>();
    let document = json!({
        "resourceLogs": [{
            "resource": {
                "attributes": [
                    string_attribute("service.name", &options.service_name),
                    string_attribute("service.version", &options.service_version),
                    string_attribute("service.namespace", "org.contextualwisdomlab"),
                    string_attribute(
                        "deployment.environment.name",
                        &options.deployment_environment,
                    ),
                    string_attribute("telemetry.sdk.name", "wardnet-event-exporter"),
                    string_attribute("telemetry.sdk.language", "rust"),
                    string_attribute("ocsf.version", OCSF_VERSION),
                ]
            },
            "scopeLogs": [{
                "scope": {
                    "name": OTEL_SCOPE_NAME,
                    "version": options.service_version,
                },
                "logRecords": log_records,
            }]
        }]
    });
    let mut output = serde_json::to_string(&document)
        .map_err(|error| ExportError::new(format!("failed to encode OTLP JSON: {error}")))?;
    output.push('\n');
    Ok(output)
}

fn otlp_log_record(event: &NormalizedEvent) -> Value {
    let severity = EventSeverity::for_event(event);
    let mut attributes = vec![
        integer_attribute("wardnet.event.id", event.id),
        integer_attribute("wardnet.event.timestamp_unix", event.timestamp_unix),
        string_attribute("security.action", &event.action),
        string_attribute("security.reason", &event.reason),
        integer_attribute("security.score", u64::from(event.score)),
        string_attribute("url.path", &event.path),
        integer_attribute("ocsf.category_uid", OCSF_CATEGORY_UID),
        integer_attribute("ocsf.class_uid", OCSF_CLASS_UID),
        integer_attribute("ocsf.type_uid", OCSF_TYPE_UID),
    ];
    if let Some(client_ip) = &event.client_ip {
        attributes.push(string_attribute("client.address", client_ip));
    }
    if let Some(route_id) = &event.route_id {
        attributes.push(string_attribute("wardnet.route.id", route_id));
    }

    let mut record = Map::new();
    record.insert(
        "timeUnixNano".to_string(),
        Value::String(event.timestamp_unix_nano.clone()),
    );
    record.insert(
        "observedTimeUnixNano".to_string(),
        Value::String(event.timestamp_unix_nano.clone()),
    );
    record.insert("severityNumber".to_string(), json!(severity.otel_number()));
    record.insert("severityText".to_string(), json!(severity.otel_text()));
    record.insert(
        "body".to_string(),
        json!({ "stringValue": event.reason }),
    );
    record.insert("attributes".to_string(), Value::Array(attributes));
    record.insert("eventName".to_string(), json!(OTEL_EVENT_NAME));

    if let Some(trace_context) = &event.trace_context {
        record.insert(
            "traceId".to_string(),
            Value::String(base64_encode(&trace_context.trace_id_bytes)),
        );
        record.insert(
            "spanId".to_string(),
            Value::String(base64_encode(&trace_context.span_id_bytes)),
        );
        record.insert("flags".to_string(), json!(trace_context.trace_flags));
    }

    Value::Object(record)
}

fn string_attribute(key: &str, value: &str) -> Value {
    json!({
        "key": key,
        "value": { "stringValue": value },
    })
}

fn integer_attribute(key: &str, value: u64) -> Value {
    json!({
        "key": key,
        "value": { "intValue": value.to_string() },
    })
}

fn render_rfc5424(
    events: &[NormalizedEvent],
    options: &Options,
) -> Result<String, ExportError> {
    let mut output = String::new();
    for event in events {
        let severity = EventSeverity::for_event(event);
        let priority = 16 * 8 + severity.syslog_severity();
        let origin = if let Some(client_ip) = &event.client_ip {
            format!(
                "[origin ip=\"{}\" software=\"Wardnet\" swVersion=\"{}\"]",
                escape_structured_data(client_ip),
                escape_structured_data(&options.service_version),
            )
        } else {
            format!(
                "[origin software=\"Wardnet\" swVersion=\"{}\"]",
                escape_structured_data(&options.service_version),
            )
        };
        let metadata = format!("[meta sequenceId=\"{}\"]", event.id);
        let trace = event.trace_context.as_ref().map_or_else(String::new, |context| {
            format!(
                concat!(
                    "[opentelemetry trace_id=\"{}\" span_id=\"{}\" ",
                    "trace_flags=\"{}\"]"
                ),
                escape_structured_data(&context.trace_id_hex),
                escape_structured_data(&context.span_id_hex),
                escape_structured_data(&context.trace_flags_hex),
            )
        });
        let message = json!({
            "schema": "org.contextualwisdomlab.wardnet.security_event.v1",
            "event_id": event.id,
            "timestamp_unix": event.timestamp_unix,
            "client_ip": event.client_ip,
            "route_id": event.route_id,
            "action": event.action,
            "reason": event.reason,
            "score": event.score,
            "path": event.path,
            "trace_id": event
                .trace_context
                .as_ref()
                .map(|context| context.trace_id_hex.as_str()),
            "span_id": event
                .trace_context
                .as_ref()
                .map(|context| context.span_id_hex.as_str()),
            "trace_flags": event
                .trace_context
                .as_ref()
                .map(|context| context.trace_flags_hex.as_str()),
        });
        let message = serde_json::to_string(&message)
            .map_err(|error| ExportError::new(format!("failed to encode syslog JSON: {error}")))?;
        output.push_str(&format!(
            "<{priority}>1 - - wardnet - WARDNET_EVENT {origin}{metadata}{trace} \u{feff}{message}\n"
        ));
    }
    Ok(output)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EventSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl EventSeverity {
    fn for_event(event: &NormalizedEvent) -> Self {
        if event.score >= 80 {
            Self::Critical
        } else if event.score >= 50 || event.action.eq_ignore_ascii_case("block") {
            Self::High
        } else if event.score >= 25 {
            Self::Medium
        } else {
            Self::Low
        }
    }

    fn caption(self) -> &'static str {
        match self {
            Self::Low => "Low",
            Self::Medium => "Medium",
            Self::High => "High",
            Self::Critical => "Critical",
        }
    }

    fn ocsf_id(self) -> u8 {
        match self {
            Self::Low => 2,
            Self::Medium => 3,
            Self::High => 4,
            Self::Critical => 5,
        }
    }

    fn otel_number(self) -> u8 {
        match self {
            Self::Low => 9,
            Self::Medium => 13,
            Self::High => 17,
            Self::Critical => 21,
        }
    }

    fn otel_text(self) -> &'static str {
        match self {
            Self::Low => "INFO",
            Self::Medium => "WARN",
            Self::High => "ERROR",
            Self::Critical => "FATAL",
        }
    }

    fn syslog_severity(self) -> u8 {
        match self {
            Self::Low => 5,
            Self::Medium => 4,
            Self::High => 3,
            Self::Critical => 2,
        }
    }
}

fn sanitize_path(path: &str) -> String {
    let boundary = path
        .char_indices()
        .find_map(|(index, character)| matches!(character, '?' | '#').then_some(index))
        .unwrap_or(path.len());
    let sanitized = sanitize_text(&path[..boundary], MAX_PATH_CHARS);
    if sanitized.is_empty() {
        "/".to_string()
    } else {
        sanitized
    }
}

fn sanitize_text(value: &str, maximum_chars: usize) -> String {
    let normalized = value
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect::<String>();
    redact_sensitive(&normalized)
        .chars()
        .take(maximum_chars)
        .collect()
}

fn redact_sensitive(value: &str) -> String {
    const KEY_PREFIXES: [&[u8]; 6] = [
        b"token=",
        b"secret=",
        b"password=",
        b"api_key=",
        b"apikey=",
        b"authorization=",
    ];

    let bytes = value.as_bytes();
    let mut output = String::with_capacity(value.len());
    let mut index = 0;
    while index < bytes.len() {
        if matches_ascii_case_insensitive(bytes, index, b"sk-") {
            output.push_str("[REDACTED]");
            index = consume_secret_value(bytes, index + 3);
            continue;
        }
        if matches_ascii_case_insensitive(bytes, index, b"bearer ") {
            output.push_str("Bearer [REDACTED]");
            index = consume_secret_value(bytes, index + 7);
            continue;
        }

        let mut matched_key = None;
        for prefix in KEY_PREFIXES {
            if matches_ascii_case_insensitive(bytes, index, prefix) {
                matched_key = Some(prefix);
                break;
            }
        }
        if let Some(prefix) = matched_key {
            output.push_str(&value[index..index + prefix.len()]);
            output.push_str("[REDACTED]");
            index = consume_secret_value(bytes, index + prefix.len());
            continue;
        }

        let character = value[index..]
            .chars()
            .next()
            .expect("index remains at a UTF-8 character boundary");
        output.push(character);
        index += character.len_utf8();
    }
    output
}

fn matches_ascii_case_insensitive(bytes: &[u8], index: usize, pattern: &[u8]) -> bool {
    bytes
        .get(index..index.saturating_add(pattern.len()))
        .is_some_and(|candidate| candidate.eq_ignore_ascii_case(pattern))
}

fn consume_secret_value(bytes: &[u8], mut index: usize) -> usize {
    while index < bytes.len() && !is_secret_delimiter(bytes[index]) {
        index += 1;
    }
    index
}

fn is_secret_delimiter(value: u8) -> bool {
    value.is_ascii_whitespace()
        || matches!(
            value,
            b'&' | b';' | b',' | b'"' | b'\'' | b']' | b'}' | b')' | b'(' | b'<' | b'>'
        )
}

fn escape_structured_data(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '\\' | '"' | ']' => {
                output.push('\\');
                output.push(character);
            }
            character if character.is_control() => output.push(' '),
            character => output.push(character),
        }
    }
    output
}

fn base64_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::with_capacity(bytes.len().saturating_add(2) / 3 * 4);
    let mut index = 0;
    while index < bytes.len() {
        let first = u32::from(bytes[index]);
        let second = bytes.get(index + 1).copied().map(u32::from);
        let third = bytes.get(index + 2).copied().map(u32::from);
        let aggregate = (first << 16) | (second.unwrap_or_default() << 8) | third.unwrap_or_default();

        output.push(ALPHABET[((aggregate >> 18) & 0x3f) as usize] as char);
        output.push(ALPHABET[((aggregate >> 12) & 0x3f) as usize] as char);
        if second.is_some() {
            output.push(ALPHABET[((aggregate >> 6) & 0x3f) as usize] as char);
        } else {
            output.push('=');
        }
        if third.is_some() {
            output.push(ALPHABET[(aggregate & 0x3f) as usize] as char);
        } else {
            output.push('=');
        }
        index += 3;
    }
    output
}
