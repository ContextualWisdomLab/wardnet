//! Convert Wardnet security-event NDJSON into vendor-neutral SIEM and
//! OpenTelemetry log formats.
//!
//! The exporter is intentionally separate from the gateway process. It reads a
//! complete bounded NDJSON batch from standard input, validates every event,
//! removes fields outside the explicit contract, redacts credential-shaped
//! values, and writes only after the entire batch has been rendered. A malformed
//! line therefore cannot produce a partial downstream export.

#![forbid(unsafe_code)]

use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::HashSet;
use std::env;
use std::io::{self, Read, Write};
use std::net::IpAddr;
use std::process::ExitCode;

const OCSF_VERSION: &str = "1.8.0";
const MAX_INPUT_BYTES: u64 = 16 * 1024 * 1024;
const MAX_LINE_BYTES: usize = 1024 * 1024;
const MAX_OUTPUT_BYTES: usize = 64 * 1024 * 1024;
const MAX_EVENTS: usize = 100_000;
const MAX_ACTION_CHARS: usize = 64;
const MAX_REASON_CHARS: usize = 2_048;
const MAX_PATH_CHARS: usize = 2_048;
const MAX_ROUTE_CHARS: usize = 256;
const OTEL_EVENT_NAME: &str = "org.contextualwisdomlab.wardnet.security.decision";
const OTEL_SCOPE_NAME: &str = "org.contextualwisdomlab.wardnet.security";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExportFormat {
    Ocsf,
    OtlpJson,
    Rfc5424,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Options {
    format: ExportFormat,
    after_id: u64,
    service_name: String,
    service_version: String,
    deployment_environment: String,
}

#[derive(Debug, Deserialize)]
struct SourceEvent {
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
struct TraceContext {
    trace_id: String,
    span_id: String,
    trace_flags: String,
    flags: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NormalizedEvent {
    id: u64,
    timestamp_unix: u64,
    client_ip: Option<String>,
    route_id: Option<String>,
    action: String,
    reason: String,
    score: u16,
    path: String,
    trace_context: Option<TraceContext>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct NormalizedSeverity {
    ocsf_id: u8,
    ocsf_name: &'static str,
    otel_number: u8,
    otel_text: &'static str,
    syslog_code: u8,
}

fn main() -> ExitCode {
    match execute(env::args().skip(1), io::stdin(), io::stdout()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("wardnet-event-exporter: {error}");
            ExitCode::FAILURE
        }
    }
}

fn execute<I, R, W>(args: I, reader: R, mut writer: W) -> Result<(), String>
where
    I: IntoIterator<Item = String>,
    R: Read,
    W: Write,
{
    let command = parse_args(args)?;
    match command {
        ParsedCommand::Help => writer
            .write_all(usage().as_bytes())
            .map_err(|error| format!("write help: {error}"))?,
        ParsedCommand::Version => writeln!(writer, "{}", env!("CARGO_PKG_VERSION"))
            .map_err(|error| format!("write version: {error}"))?,
        ParsedCommand::Export(options) => {
            let events = read_events(reader)?;
            let selected: Vec<_> = events
                .into_iter()
                .filter(|event| event.id > options.after_id)
                .collect();
            let rendered = render(&options, &selected)?;
            if rendered.len() > MAX_OUTPUT_BYTES {
                return Err(format!(
                    "rendered output exceeds the {MAX_OUTPUT_BYTES}-byte limit"
                ));
            }
            writer
                .write_all(rendered.as_bytes())
                .map_err(|error| format!("write export: {error}"))?;
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ParsedCommand {
    Export(Options),
    Help,
    Version,
}

fn parse_args<I>(args: I) -> Result<ParsedCommand, String>
where
    I: IntoIterator<Item = String>,
{
    let args: Vec<String> = args.into_iter().collect();
    let mut format = None;
    let mut after_id = 0;
    let mut service_name = "wardnet".to_string();
    let mut service_version = env!("CARGO_PKG_VERSION").to_string();
    let mut deployment_environment = "unspecified".to_string();
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--help" | "-h" => return Ok(ParsedCommand::Help),
            "--version" | "-V" => return Ok(ParsedCommand::Version),
            "--format" => {
                let value = required_value(&args, index, "--format")?;
                format = Some(match value {
                    "ocsf" => ExportFormat::Ocsf,
                    "otlp-json" => ExportFormat::OtlpJson,
                    "rfc5424" => ExportFormat::Rfc5424,
                    _ => return Err(format!("unsupported format: {value}")),
                });
                index += 2;
            }
            "--after-id" => {
                let value = required_value(&args, index, "--after-id")?;
                after_id = value
                    .parse::<u64>()
                    .map_err(|_| format!("invalid --after-id value: {value}"))?;
                index += 2;
            }
            "--service-name" => {
                let value = required_value(&args, index, "--service-name")?;
                service_name = validated_label("service name", value, 128)?;
                index += 2;
            }
            "--service-version" => {
                let value = required_value(&args, index, "--service-version")?;
                service_version = validated_label("service version", value, 128)?;
                index += 2;
            }
            "--deployment-environment" => {
                let value = required_value(&args, index, "--deployment-environment")?;
                deployment_environment = validated_label("deployment environment", value, 128)?;
                index += 2;
            }
            option => return Err(format!("unknown option: {option}")),
        }
    }

    let format = format
        .ok_or_else(|| "missing required --format (ocsf, otlp-json, or rfc5424)".to_string())?;

    Ok(ParsedCommand::Export(Options {
        format,
        after_id,
        service_name,
        service_version,
        deployment_environment,
    }))
}

fn required_value<'a>(args: &'a [String], index: usize, option: &str) -> Result<&'a str, String> {
    args.get(index + 1)
        .map(String::as_str)
        .filter(|value| !value.starts_with("--"))
        .ok_or_else(|| format!("missing value for {option}"))
}

fn validated_label(label: &str, value: &str, maximum: usize) -> Result<String, String> {
    let length = value.chars().count();
    if length == 0 || length > maximum {
        return Err(format!(
            "{label} must contain between 1 and {maximum} characters"
        ));
    }
    if value.chars().any(char::is_control) {
        return Err(format!("{label} contains a control character"));
    }
    if contains_secret_marker(value) {
        return Err(format!("{label} contains credential-shaped material"));
    }
    Ok(value.to_string())
}

fn usage() -> &'static str {
    concat!(
        "Wardnet SIEM and OpenTelemetry event exporter\n\n",
        "USAGE:\n",
        "  wardnet-event-exporter --format <ocsf|otlp-json|rfc5424> [OPTIONS] < events.ndjson\n\n",
        "OPTIONS:\n",
        "  --after-id <ID>                    Export only events with a larger ID\n",
        "  --service-name <NAME>              OTLP service.name (default: wardnet)\n",
        "  --service-version <VERSION>         OTLP service.version\n",
        "  --deployment-environment <NAME>    OTLP deployment.environment.name\n",
        "  -h, --help                         Print help\n",
        "  -V, --version                      Print version\n"
    )
}

fn read_events<R: Read>(reader: R) -> Result<Vec<NormalizedEvent>, String> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_INPUT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("read standard input: {error}"))?;
    if bytes.len() as u64 > MAX_INPUT_BYTES {
        return Err(format!("input exceeds the {MAX_INPUT_BYTES}-byte limit"));
    }
    let input = String::from_utf8(bytes).map_err(|_| "input is not valid UTF-8".to_string())?;

    let mut events = Vec::new();
    let mut event_ids = HashSet::new();
    for (line_index, line) in input.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let line_number = line_index + 1;
        if line.len() > MAX_LINE_BYTES {
            return Err(format!(
                "line {line_number} exceeds the {MAX_LINE_BYTES}-byte limit"
            ));
        }
        if events.len() >= MAX_EVENTS {
            return Err(format!("input contains more than {MAX_EVENTS} events"));
        }
        let source: SourceEvent = serde_json::from_str(line)
            .map_err(|error| format!("line {line_number}: invalid event JSON: {error}"))?;
        if !event_ids.insert(source.id) {
            return Err(format!(
                "line {line_number}: duplicate event id {}",
                source.id
            ));
        }
        events.push(normalize_event(source, line_number)?);
    }
    Ok(events)
}

fn normalize_event(source: SourceEvent, line_number: usize) -> Result<NormalizedEvent, String> {
    if source.id == 0 {
        return Err(format!("line {line_number}: event id must be positive"));
    }
    if source.timestamp_unix == 0 {
        return Err(format!(
            "line {line_number}: timestamp_unix must be positive"
        ));
    }
    checked_time(source.timestamp_unix, 1_000_000_000, line_number)?;
    let action = required_sanitized("action", &source.action, MAX_ACTION_CHARS, line_number)?;
    let reason = required_sanitized("reason", &source.reason, MAX_REASON_CHARS, line_number)?;
    let path = sanitize_path(&source.path, line_number)?;
    let route_id = source
        .route_id
        .as_deref()
        .map(|route| required_sanitized("route_id", route, MAX_ROUTE_CHARS, line_number))
        .transpose()?;
    let trace_context = validate_trace_context(
        source.trace_id.as_deref(),
        source.span_id.as_deref(),
        source.trace_flags.as_deref(),
        line_number,
    )?;

    Ok(NormalizedEvent {
        id: source.id,
        timestamp_unix: source.timestamp_unix,
        client_ip: source.client_ip.map(|address| address.to_string()),
        route_id,
        action,
        reason,
        score: source.score,
        path,
        trace_context,
    })
}

fn required_sanitized(
    field: &str,
    value: &str,
    maximum: usize,
    line_number: usize,
) -> Result<String, String> {
    if value.is_empty() {
        return Err(format!("line {line_number}: {field} must not be empty"));
    }
    if value.chars().count() > maximum {
        return Err(format!(
            "line {line_number}: {field} exceeds the {maximum}-character limit"
        ));
    }
    let sanitized = sanitize_text(value, maximum);
    if sanitized.is_empty() {
        return Err(format!(
            "line {line_number}: {field} contains no exportable text"
        ));
    }
    Ok(sanitized)
}

fn sanitize_path(value: &str, line_number: usize) -> Result<String, String> {
    if value.is_empty() {
        return Err(format!("line {line_number}: path must not be empty"));
    }
    if value.chars().count() > MAX_PATH_CHARS {
        return Err(format!(
            "line {line_number}: path exceeds the {MAX_PATH_CHARS}-character limit"
        ));
    }
    let end = value
        .char_indices()
        .find_map(|(index, character)| matches!(character, '?' | '#').then_some(index))
        .unwrap_or(value.len());
    let path = sanitize_text(&value[..end], MAX_PATH_CHARS);
    if path.is_empty() {
        Ok("/".to_string())
    } else {
        Ok(path)
    }
}

fn sanitize_text(value: &str, maximum: usize) -> String {
    let normalized: String = value
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect();

    let mut output = String::new();
    let mut redact_next = false;
    for token in normalized.split_whitespace() {
        if !output.is_empty() {
            output.push(' ');
        }
        let redacted = if redact_next {
            "[REDACTED]".to_string()
        } else {
            redact_token(token)
        };
        output.push_str(&redacted);
        redact_next = is_authorization_marker(token);
    }
    truncate_chars(&output, maximum)
}

fn is_authorization_marker(token: &str) -> bool {
    let marker = token.trim_end_matches(':');
    marker.eq_ignore_ascii_case("bearer") || marker.eq_ignore_ascii_case("authorization")
}

fn redact_token(token: &str) -> String {
    const ASSIGNMENT_KEYS: [&str; 7] = [
        "access_token=",
        "api_key=",
        "apikey=",
        "authorization=",
        "password=",
        "secret=",
        "token=",
    ];
    let lower = token.to_ascii_lowercase();
    for key in ASSIGNMENT_KEYS {
        if let Some(index) = lower.find(key) {
            return format!(
                "{}{}[REDACTED]",
                &token[..index],
                &token[index..index + key.len()]
            );
        }
    }

    const SECRET_PREFIXES: [&str; 6] = ["sk-", "ghp_", "github_pat_", "xoxb-", "xoxp-", "AIza"];
    for prefix in SECRET_PREFIXES {
        if let Some(index) = secret_prefix_index(token, prefix) {
            return format!("{}[REDACTED]", &token[..index]);
        }
    }
    token.to_string()
}

fn secret_prefix_index(token: &str, prefix: &str) -> Option<usize> {
    token.match_indices(prefix).find_map(|(index, _)| {
        let boundary = match token[..index].chars().next_back() {
            None => true,
            Some(character) => !character.is_ascii_alphanumeric() && character != '_',
        };
        boundary.then_some(index)
    })
}

fn contains_secret_marker(value: &str) -> bool {
    let mut redact_next = false;
    for token in value.split_whitespace() {
        if redact_next || redact_token(token) != token {
            return true;
        }
        redact_next = is_authorization_marker(token);
    }
    false
}

fn truncate_chars(value: &str, maximum: usize) -> String {
    if value.chars().count() <= maximum {
        return value.to_string();
    }
    value.chars().take(maximum).collect()
}

fn validate_trace_context(
    trace_id: Option<&str>,
    span_id: Option<&str>,
    trace_flags: Option<&str>,
    line_number: usize,
) -> Result<Option<TraceContext>, String> {
    match (trace_id, span_id, trace_flags) {
        (None, None, None) => Ok(None),
        (Some(trace_id), Some(span_id), flags) => {
            let trace_id = validate_hex_identifier("trace id", trace_id, 32, line_number)?;
            let span_id = validate_hex_identifier("span id", span_id, 16, line_number)?;
            let trace_flags = flags.unwrap_or("00");
            if trace_flags.len() != 2 || !trace_flags.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Err(format!(
                    "line {line_number}: trace context has invalid trace flags"
                ));
            }
            let normalized_flags = trace_flags.to_ascii_lowercase();
            let flags = u8::from_str_radix(&normalized_flags, 16).map_err(|_| {
                format!("line {line_number}: trace context has invalid trace flags")
            })?;
            Ok(Some(TraceContext {
                trace_id,
                span_id,
                trace_flags: normalized_flags,
                flags,
            }))
        }
        _ => Err(format!(
            "line {line_number}: trace context requires trace_id and span_id together"
        )),
    }
}

fn validate_hex_identifier(
    label: &str,
    value: &str,
    required_length: usize,
    line_number: usize,
) -> Result<String, String> {
    if value.len() != required_length
        || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
        || value.bytes().all(|byte| byte == b'0')
    {
        return Err(format!(
            "line {line_number}: trace context has invalid {label}"
        ));
    }
    Ok(value.to_ascii_lowercase())
}

fn checked_time(value: u64, multiplier: u64, line_number: usize) -> Result<u64, String> {
    value
        .checked_mul(multiplier)
        .ok_or_else(|| format!("line {line_number}: timestamp_unix is out of range"))
}

fn render(options: &Options, events: &[NormalizedEvent]) -> Result<String, String> {
    match options.format {
        ExportFormat::Ocsf => render_json_lines(events, render_ocsf),
        ExportFormat::OtlpJson => render_otlp(options, events),
        ExportFormat::Rfc5424 => render_rfc5424(events),
    }
}

fn render_json_lines<F>(events: &[NormalizedEvent], render_event: F) -> Result<String, String>
where
    F: Fn(&NormalizedEvent) -> Result<Value, String>,
{
    let mut output = String::new();
    for event in events {
        let value = render_event(event)?;
        let line = serde_json::to_string(&value)
            .map_err(|error| format!("serialize exported event {}: {error}", event.id))?;
        output.push_str(&line);
        output.push('\n');
    }
    Ok(output)
}

fn render_ocsf(event: &NormalizedEvent) -> Result<Value, String> {
    let severity = severity(event.score);
    let time = checked_time(event.timestamp_unix, 1_000, 0)
        .map_err(|_| format!("event {} timestamp is out of OCSF range", event.id))?;
    let (action_id, action_name) = ocsf_action(&event.action);
    let product = json!({
        "name": "Wardnet",
        "vendor_name": "ContextualWisdomLab",
        "version": env!("CARGO_PKG_VERSION")
    });

    Ok(json!({
        "activity_id": 1,
        "activity_name": "Create",
        "action": action_name,
        "action_id": action_id,
        "category_name": "Findings",
        "category_uid": 2,
        "class_name": "Detection Finding",
        "class_uid": 2004,
        "finding_info": {
            "created_time": time,
            "desc": event.reason.as_str(),
            "product": product.clone(),
            "title": format!("Wardnet {} security decision", event.action),
            "types": ["WAF/IDS Security Decision"],
            "uid": format!("wardnet-event-{}", event.id)
        },
        "is_alert": event.score > 0 || action_id == 2,
        "message": format!("Wardnet {} security decision: {}", event.action, event.reason),
        "metadata": {
            "log_format": "JSON",
            "log_name": "wardnet_security_events",
            "log_source": "Wardnet /api/events.ndjson",
            "original_event_uid": event.id.to_string(),
            "product": product,
            "profiles": ["security_control"],
            "uid": format!("wardnet-ocsf-{}", event.id),
            "version": OCSF_VERSION
        },
        "risk_score": event.score.min(100),
        "severity": severity.ocsf_name,
        "severity_id": severity.ocsf_id,
        "status": "New",
        "status_id": 1,
        "time": time,
        "timezone_offset": 0,
        "type_name": "Detection Finding: Create",
        "type_uid": 200401,
        "unmapped": {
            "wardnet": {
                "action": event.action.as_str(),
                "client_ip": event.client_ip.as_deref(),
                "path": event.path.as_str(),
                "reason": event.reason.as_str(),
                "route_id": event.route_id.as_deref(),
                "score": event.score,
                "timestamp_unix": event.timestamp_unix,
                "trace_flags": event.trace_context.as_ref().map(|context| context.trace_flags.as_str()),
                "trace_id": event.trace_context.as_ref().map(|context| context.trace_id.as_str()),
                "span_id": event.trace_context.as_ref().map(|context| context.span_id.as_str())
            }
        }
    }))
}

fn ocsf_action(action: &str) -> (u8, &str) {
    if ["block", "blocked", "deny", "denied", "drop", "dropped"]
        .iter()
        .any(|candidate| action.eq_ignore_ascii_case(candidate))
    {
        (2, "Denied")
    } else if ["allow", "allowed", "approve", "approved"]
        .iter()
        .any(|candidate| action.eq_ignore_ascii_case(candidate))
    {
        (1, "Allowed")
    } else if ["monitor", "monitored", "observe", "observed", "alert"]
        .iter()
        .any(|candidate| action.eq_ignore_ascii_case(candidate))
    {
        (3, "Observed")
    } else {
        (99, action)
    }
}

fn render_otlp(options: &Options, events: &[NormalizedEvent]) -> Result<String, String> {
    if events.is_empty() {
        return Ok("{\"resourceLogs\":[]}\n".to_string());
    }

    let mut records = Vec::with_capacity(events.len());
    for event in events {
        records.push(otlp_log_record(event)?);
    }

    let value = json!({
        "resourceLogs": [{
            "resource": {
                "attributes": [
                    otlp_string_attribute("deployment.environment.name", &options.deployment_environment),
                    otlp_string_attribute("service.name", &options.service_name),
                    otlp_string_attribute("service.namespace", "org.contextualwisdomlab"),
                    otlp_string_attribute("service.version", &options.service_version),
                    otlp_string_attribute("wardnet.exporter.name", "wardnet-event-exporter"),
                    otlp_string_attribute("wardnet.exporter.version", env!("CARGO_PKG_VERSION"))
                ]
            },
            "scopeLogs": [{
                "scope": {
                    "name": OTEL_SCOPE_NAME,
                    "version": env!("CARGO_PKG_VERSION")
                },
                "logRecords": records
            }]
        }]
    });
    let mut output = serde_json::to_string(&value)
        .map_err(|error| format!("serialize OTLP JSON request: {error}"))?;
    output.push('\n');
    Ok(output)
}

fn otlp_log_record(event: &NormalizedEvent) -> Result<Value, String> {
    let severity = severity(event.score);
    let timestamp = checked_time(event.timestamp_unix, 1_000_000_000, 0)
        .map_err(|_| format!("event {} timestamp is out of OTLP range", event.id))?;
    let mut attributes = vec![
        otlp_string_attribute("event.domain", "security"),
        otlp_string_attribute("url.path", &event.path),
        otlp_int_attribute("wardnet.event.id", event.id),
        otlp_string_attribute("wardnet.security.action", &event.action),
        otlp_string_attribute("wardnet.security.reason", &event.reason),
        otlp_int_attribute("wardnet.security.score", u64::from(event.score)),
    ];
    if let Some(route_id) = &event.route_id {
        attributes.push(otlp_string_attribute("wardnet.route.id", route_id));
    }
    if let Some(client_ip) = &event.client_ip {
        attributes.push(otlp_string_attribute("client.address", client_ip));
    }

    let mut record = json!({
        "attributes": attributes,
        "body": {
            "stringValue": format!("Wardnet {} security decision: {}", event.action, event.reason)
        },
        "eventName": OTEL_EVENT_NAME,
        "severityNumber": severity.otel_number,
        "severityText": severity.otel_text,
        "timeUnixNano": timestamp.to_string()
    });
    if let Some(trace_context) = &event.trace_context {
        let object = record
            .as_object_mut()
            .ok_or_else(|| format!("event {} OTLP record is not an object", event.id))?;
        object.insert("flags".to_string(), json!(trace_context.flags));
        object.insert("spanId".to_string(), json!(trace_context.span_id));
        object.insert("traceId".to_string(), json!(trace_context.trace_id));
    }
    Ok(record)
}

fn otlp_string_attribute(key: &str, value: &str) -> Value {
    json!({
        "key": key,
        "value": {"stringValue": value}
    })
}

fn otlp_int_attribute(key: &str, value: u64) -> Value {
    json!({
        "key": key,
        "value": {"intValue": value.to_string()}
    })
}

fn render_rfc5424(events: &[NormalizedEvent]) -> Result<String, String> {
    let mut output = String::new();
    for event in events {
        let severity = severity(event.score);
        let priority = 16_u16 * 8 + u16::from(severity.syslog_code);
        let ip_parameter = event
            .client_ip
            .as_deref()
            .map_or_else(String::new, |client_ip| {
                format!(" ip=\"{}\"", escape_structured_data(client_ip))
            });
        let origin_data = format!(
            "[origin{ip_parameter} software=\"Wardnet\" swVersion=\"{}\"]",
            escape_structured_data(env!("CARGO_PKG_VERSION"))
        );
        let meta_data = format!("[meta sequenceId=\"{}\"]", event.id);
        let trace_data = event
            .trace_context
            .as_ref()
            .map_or_else(String::new, |context| {
                format!(
                    "[OpenTelemetry trace_id=\"{}\" span_id=\"{}\" trace_flags=\"{}\"]",
                    context.trace_id, context.span_id, context.trace_flags
                )
            });
        let message = serde_json::to_string(&json!({
            "action": event.action.as_str(),
            "client_ip": event.client_ip.as_deref(),
            "event_id": event.id,
            "path": event.path.as_str(),
            "reason": event.reason.as_str(),
            "route_id": event.route_id.as_deref(),
            "score": event.score,
            "timestamp_unix": event.timestamp_unix
        }))
        .map_err(|error| format!("serialize RFC 5424 event {}: {error}", event.id))?;
        output.push_str(&format!(
            "<{priority}>1 - - wardnet - WARDNET_EVENT {origin_data}{meta_data}{trace_data} \u{feff}{message}\n"
        ));
    }
    Ok(output)
}

fn escape_structured_data(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '\\' | '"' | ']' => {
                escaped.push('\\');
                escaped.push(character);
            }
            character if character.is_control() => escaped.push(' '),
            character => escaped.push(character),
        }
    }
    escaped
}

fn severity(score: u16) -> NormalizedSeverity {
    match score {
        0 => NormalizedSeverity {
            ocsf_id: 1,
            ocsf_name: "Informational",
            otel_number: 9,
            otel_text: "INFO",
            syslog_code: 6,
        },
        1..=19 => NormalizedSeverity {
            ocsf_id: 2,
            ocsf_name: "Low",
            otel_number: 10,
            otel_text: "INFO2",
            syslog_code: 5,
        },
        20..=49 => NormalizedSeverity {
            ocsf_id: 3,
            ocsf_name: "Medium",
            otel_number: 13,
            otel_text: "WARN",
            syslog_code: 4,
        },
        50..=79 => NormalizedSeverity {
            ocsf_id: 4,
            ocsf_name: "High",
            otel_number: 17,
            otel_text: "ERROR",
            syslog_code: 3,
        },
        _ => NormalizedSeverity {
            ocsf_id: 5,
            ocsf_name: "Critical",
            otel_number: 21,
            otel_text: "FATAL",
            syslog_code: 2,
        },
    }
}
