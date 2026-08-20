//! Fail-closed input and RFC 5424 timestamp contracts for the Wardnet exporter.

use std::io::Write;
use std::process::{Command, Output, Stdio};

const TRACE_ID: &str = "4bf92f3577b34da6a3ce929d0e0e4736";
const SPAN_ID: &str = "00f067aa0ba902b7";

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

fn event(id: u64, timestamp_unix: u64) -> String {
    format!(concat!(
        "{{\"id\":{id},\"timestamp_unix\":{timestamp_unix},",
        "\"client_ip\":\"203.0.113.8\",\"route_id\":\"checkout\",",
        "\"action\":\"block\",\"reason\":\"rule match\",",
        "\"score\":55,\"path\":\"/pay\"}}\n"
    ))
}

#[test]
fn zero_and_non_increasing_event_ids_fail_closed() {
    for input in [
        event(0, 1_723_456_789),
        format!("{}{}", event(7, 1_723_456_789), event(7, 1_723_456_790)),
        format!("{}{}", event(8, 1_723_456_789), event(7, 1_723_456_790)),
    ] {
        let output = exporter(&["--format", "ocsf"], &input);
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(String::from_utf8_lossy(&output.stderr).contains("event id"));
    }
}

#[test]
fn oversized_line_and_batch_fail_closed() {
    let oversized_reason = "x".repeat(1_048_577);
    let oversized_line = format!(concat!(
        "{{\"id\":1,\"timestamp_unix\":1723456789,",
        "\"client_ip\":null,\"route_id\":null,\"action\":\"monitor\",",
        "\"reason\":\"{oversized_reason}\",\"score\":1,\"path\":\"/\"}}\n"
    ));
    let output = exporter(&["--format", "ocsf"], &oversized_line);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("line 1"));

    let mut oversized_batch = String::new();
    for id in 1..=10_001 {
        oversized_batch.push_str(&event(id, 1_723_456_789));
    }
    let output = exporter(&["--format", "ocsf"], &oversized_batch);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("event limit"));
}

#[test]
fn unsupported_trace_flags_fail_closed() {
    let input = format!(concat!(
        "{{\"id\":12,\"timestamp_unix\":1723456794,",
        "\"client_ip\":null,\"route_id\":null,\"action\":\"monitor\",",
        "\"reason\":\"rule match\",\"score\":1,\"path\":\"/\",",
        "\"trace_id\":\"{TRACE_ID}\",\"span_id\":\"{SPAN_ID}\",",
        "\"trace_flags\":\"02\"}}\n"
    ));
    let output = exporter(&["--format", "otlp-json"], &input);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("trace_flags"));
}

#[test]
fn rfc5424_header_contains_the_event_timestamp() {
    let output = exporter(&["--format", "rfc5424"], &event(13, 1_723_456_791));
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let body = String::from_utf8(output.stdout).expect("UTF-8 syslog output");
    assert!(body.starts_with("<131>1 2024-08-12T09:59:51Z - wardnet - WARDNET_EVENT "));
}
