//! End-to-end contracts for the Wardnet SIEM and OpenTelemetry exporter.

use serde_json::Value;
use std::io::Write;
use std::process::{Command, Output, Stdio};

const TRACE_ID: &str = "4bf92f3577b34da6a3ce929d0e0e4736";
const SPAN_ID: &str = "00f067aa0ba902b7";
const OTLP_TRACE_ID: &str = "S/kvNXezTaajzpKdDg5HNg==";
const OTLP_SPAN_ID: &str = "APBnqgupArc=";
const SECRET_CANARY: &str = "sk-live-wardnet-canary";

fn exporter(args: &[&str], input: &str) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_wardnet-event-exporter"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn Wardnet event exporter");

    child
        .stdin
        .take()
        .expect("exporter stdin")
        .write_all(input.as_bytes())
        .expect("write exporter input");

    child.wait_with_output().expect("wait for exporter")
}

fn event(id: u64, timestamp_unix: u64, score: u16) -> String {
    format!(
        concat!(
            "{{\"id\":{id},\"timestamp_unix\":{timestamp_unix},",
            "\"client_ip\":\"203.0.113.8\",\"route_id\":\"checkout\",",
            "\"action\":\"block\",",
            "\"reason\":\"sqli\\ncredential {secret}\",",
            "\"score\":{score},",
            "\"path\":\"/pay?token={secret}#fragment\",",
            "\"trace_id\":\"{trace_id}\",\"span_id\":\"{span_id}\",",
            "\"trace_flags\":\"01\",",
            "\"untrusted_extra\":\"{secret}\"}}\n"
        ),
        secret = SECRET_CANARY,
        trace_id = TRACE_ID,
        span_id = SPAN_ID,
    )
}

#[test]
fn ocsf_detection_finding_is_versioned_allowlisted_and_redacted() {
    let output = exporter(&["--format", "ocsf"], &event(7, 1_723_456_789, 80));
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let body = String::from_utf8(output.stdout).expect("UTF-8 OCSF output");
    assert!(!body.contains(SECRET_CANARY));
    let value: Value = serde_json::from_str(body.trim()).expect("valid OCSF JSON line");

    assert_eq!(value["category_uid"], 2);
    assert_eq!(value["class_uid"], 2004);
    assert_eq!(value["type_uid"], 200401);
    assert_eq!(value["activity_id"], 1);
    assert_eq!(value["metadata"]["version"], "1.8.0");
    assert_eq!(value["metadata"]["original_event_uid"], "7");
    assert_eq!(value["metadata"]["product"]["name"], "Wardnet");
    assert_eq!(value["finding_info"]["uid"], "wardnet-event-7");
    assert_eq!(value["unmapped"]["wardnet"]["client_ip"], "203.0.113.8");
    assert_eq!(value["unmapped"]["wardnet"]["path"], "/pay");
    assert_eq!(value["unmapped"]["wardnet"]["score"], 80);
    assert!(value.get("untrusted_extra").is_none());
}

#[test]
fn otlp_json_filters_checkpoint_and_preserves_trace_context() {
    let input = format!(
        "{}{}",
        event(7, 1_723_456_789, 10),
        event(8, 1_723_456_790, 55)
    );
    let output = exporter(
        &[
            "--format",
            "otlp-json",
            "--after-id",
            "7",
            "--service-name",
            "wardnet-edge",
            "--deployment-environment",
            "test",
        ],
        &input,
    );
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let body = String::from_utf8(output.stdout).expect("UTF-8 OTLP output");
    assert!(!body.contains(SECRET_CANARY));
    let value: Value = serde_json::from_str(&body).expect("valid OTLP JSON request");
    let resource_log = &value["resourceLogs"][0];
    let records = resource_log["scopeLogs"][0]["logRecords"]
        .as_array()
        .expect("OTLP log records");
    assert_eq!(records.len(), 1);

    let record = &records[0];
    assert_eq!(record["timeUnixNano"], "1723456790000000000");
    assert_eq!(record["traceId"], OTLP_TRACE_ID);
    assert_eq!(record["spanId"], OTLP_SPAN_ID);
    assert_eq!(record["flags"], 1);
    assert_eq!(
        record["eventName"],
        "org.contextualwisdomlab.wardnet.security.decision"
    );

    let attributes = record["attributes"].as_array().expect("OTLP attributes");
    assert!(attributes.iter().any(|attribute| {
        attribute["key"] == "wardnet.event.id" && attribute["value"]["intValue"] == "8"
    }));

    let resource_attributes = resource_log["resource"]["attributes"]
        .as_array()
        .expect("resource attributes");
    assert!(resource_attributes.iter().any(|attribute| {
        attribute["key"] == "service.name" && attribute["value"]["stringValue"] == "wardnet-edge"
    }));
    assert!(resource_attributes.iter().any(|attribute| {
        attribute["key"] == "deployment.environment.name"
            && attribute["value"]["stringValue"] == "test"
    }));
}

#[test]
fn rfc5424_uses_standard_structured_data_and_single_line_json_message() {
    let output = exporter(&["--format", "rfc5424"], &event(9, 1_723_456_791, 55));
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let body = String::from_utf8(output.stdout).expect("UTF-8 syslog output");
    assert_eq!(body.lines().count(), 1);
    assert!(body.starts_with("<131>1 - - wardnet - WARDNET_EVENT "));
    assert!(body.contains("[origin ip=\"203.0.113.8\" software=\"Wardnet\""));
    assert!(body.contains("[meta sequenceId=\"9\"]"));
    assert!(body.contains(&format!(
        "[opentelemetry trace_id=\"{TRACE_ID}\" span_id=\"{SPAN_ID}\" trace_flags=\"01\"]"
    )));
    assert!(body.contains('\u{feff}'));
    assert!(body.contains("\"event_id\":9"));
    assert!(body.contains("\"timestamp_unix\":1723456791"));
    assert!(!body.contains("[wardnet"));
    assert!(!body.contains("@32473"));
    assert!(!body.contains(SECRET_CANARY));
    assert!(!body.contains("?token="));
}

#[test]
fn malformed_input_fails_closed_without_partial_output() {
    let input = format!("{}{{not-json}}\n", event(10, 1_723_456_792, 10));
    let output = exporter(&["--format", "ocsf"], &input);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("line 2"));
}

#[test]
fn incomplete_or_invalid_trace_context_is_rejected() {
    let input = concat!(
        "{\"id\":11,\"timestamp_unix\":1723456793,",
        "\"client_ip\":null,\"route_id\":null,\"action\":\"monitor\",",
        "\"reason\":\"rule match\",\"score\":1,\"path\":\"/\",",
        "\"trace_id\":\"00000000000000000000000000000000\"}\n"
    );
    let output = exporter(&["--format", "otlp-json"], input);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("trace context"));
}

#[test]
fn unknown_format_and_unknown_option_are_rejected() {
    let bad_format = exporter(&["--format", "cef"], "");
    assert!(!bad_format.status.success());
    assert!(String::from_utf8_lossy(&bad_format.stderr).contains("unsupported format"));

    let bad_option = exporter(&["--unknown"], "");
    assert!(!bad_option.status.success());
    assert!(String::from_utf8_lossy(&bad_option.stderr).contains("unknown option"));
}
