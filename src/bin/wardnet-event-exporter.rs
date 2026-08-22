//! Convert Wardnet security-event NDJSON into vendor-neutral SIEM and
//! OpenTelemetry log formats.
//!
//! The exporter is intentionally separate from the gateway process. It reads a
//! complete bounded NDJSON batch from standard input, validates every event,
//! removes fields outside the explicit contract, redacts credential-shaped
//! values, and writes only after the entire batch has been rendered. A malformed
//! line therefore cannot produce a partial downstream export.

#![forbid(unsafe_code)]

use serde_json::{Value, json};
use std::env;
use std::io::{self, Read, Write};
use std::process::ExitCode;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use waf_ids_ai_soc::siem_event_input::{
    NormalizedEvent, checked_time, contains_secret_marker, read_events,
};

const OCSF_VERSION: &str = "1.8.0";
const MAX_OUTPUT_BYTES: usize = 64 * 1024 * 1024;
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

/// Map a Wardnet action to an OCSF 1.8.0 `action_id`. The dictionary's
/// `action_id` enum defines only 0 (Unknown), 1 (Allowed), 2 (Denied), and
/// 99 (Other) -- there is no "Observed" value, so `monitor`/`observe`/`alert`
/// use 99 with the human-readable caption carried in the free-text `action`
/// field, per OCSF's documented convention for values the enum doesn't
/// cover. A strict schema validator rejects any other integer here.
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
        (99, "Observed")
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
        let timestamp = rfc5424_timestamp(event.timestamp_unix)?;
        let meta_data = if event.id <= i32::MAX as u64 {
            format!("[meta sequenceId=\"{}\"]", event.id)
        } else {
            String::new()
        };
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
            "<{priority}>1 {timestamp} - wardnet - WARDNET_EVENT {origin_data}{meta_data}{trace_data} \u{feff}{message}\n"
        ));
    }
    Ok(output)
}

fn rfc5424_timestamp(timestamp_unix: u64) -> Result<String, String> {
    let timestamp = i64::try_from(timestamp_unix)
        .map_err(|_| "RFC 5424 timestamp exceeds the supported range".to_string())?;
    OffsetDateTime::from_unix_timestamp(timestamp)
        .map_err(|error| format!("invalid RFC 5424 timestamp: {error}"))?
        .format(&Rfc3339)
        .map_err(|error| format!("format RFC 5424 timestamp: {error}"))
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
