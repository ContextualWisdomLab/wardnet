//! Stable property-test mirror for the production SIEM NDJSON parser.

use proptest::prelude::*;
use std::io::Cursor;
use waf_ids_ai_soc::siem_event_input::read_events;
use waf_ids_core::MAX_ROUTE_ID_CHARS;

fn event(id: u64, timestamp_unix: u64, action: &str, reason: &str, path: &str) -> String {
    serde_json::json!({
        "id": id,
        "timestamp_unix": timestamp_unix,
        "client_ip": "203.0.113.9",
        "route_id": "checkout",
        "action": action,
        "reason": reason,
        "score": 55,
        "path": path
    })
    .to_string()
        + "\n"
}

proptest! {
    #[test]
    fn arbitrary_bounded_bytes_never_panic(input in proptest::collection::vec(any::<u8>(), 0..65_536)) {
        let _ = read_events(Cursor::new(input));
    }

    #[test]
    fn valid_events_preserve_identity_and_strip_query(
        id in 1_u64..1_000_000,
        timestamp_unix in 1_u64..4_000_000_000,
        score in 0_u16..=100,
        suffix in "[a-zA-Z0-9_-]{0,32}"
    ) {
        let input = serde_json::json!({
            "id": id,
            "timestamp_unix": timestamp_unix,
            "client_ip": "203.0.113.9",
            "route_id": "route_one",
            "action": "monitor",
            "reason": "rule match",
            "score": score,
            "path": format!("/resource/{suffix}?token=do-not-export#fragment")
        }).to_string() + "\n";
        let events = read_events(Cursor::new(input)).expect("valid event");
        prop_assert_eq!(events.len(), 1);
        prop_assert_eq!(events[0].id, id);
        prop_assert_eq!(events[0].timestamp_unix, timestamp_unix);
        prop_assert!(!events[0].path.contains('?'));
        prop_assert!(!events[0].path.contains('#'));
        prop_assert!(!events[0].path.contains("do-not-export"));
    }
}

#[test]
fn invalid_json_duplicate_and_decreasing_ids_fail_closed() {
    assert!(read_events(Cursor::new(b"{not-json}\n")).is_err());

    let duplicate = format!(
        "{}{}",
        event(7, 1_723_456_789, "monitor", "rule", "/a"),
        event(7, 1_723_456_790, "monitor", "rule", "/b")
    );
    assert!(read_events(Cursor::new(duplicate)).is_err());

    let decreasing = format!(
        "{}{}",
        event(8, 1_723_456_789, "monitor", "rule", "/a"),
        event(7, 1_723_456_790, "monitor", "rule", "/b")
    );
    assert!(read_events(Cursor::new(decreasing)).is_err());
}

#[test]
fn line_and_input_limits_fail_closed() {
    let oversized_line = "x".repeat(1_048_577);
    assert!(read_events(Cursor::new(oversized_line)).is_err());

    let oversized_input = vec![b'x'; 16 * 1024 * 1024 + 1];
    assert!(read_events(Cursor::new(oversized_input)).is_err());
}

#[test]
fn normalization_redacts_colon_and_equals_credentials() {
    let input = event(
        9,
        1_723_456_789,
        "monitor",
        "token: abc password=hunter2 api_key: xyz authorization=opaque",
        "/pay?secret=value",
    );
    let events = read_events(Cursor::new(input)).expect("valid sanitized event");
    let reason = &events[0].reason;
    for secret in ["abc", "hunter2", "xyz", "opaque"] {
        assert!(!reason.contains(secret));
    }
    assert!(reason.contains("[REDACTED]"));
    assert_eq!(events[0].path, "/pay");
}

#[test]
fn normalization_redacts_whitespace_delimited_assignments() {
    let input = event(
        1,
        1_723_456_789,
        "monitor",
        "token = alpha password :bravo api_key: charlie Authorization: Bearer delta",
        "/",
    );
    let events = read_events(Cursor::new(input)).expect("valid sanitized event");
    let reason = &events[0].reason;

    for secret in ["alpha", "bravo", "charlie", "delta"] {
        assert!(
            !reason.contains(secret),
            "leaked a fixture secret in {reason}"
        );
    }
    assert!(reason.contains("token = [REDACTED]"));
    assert!(reason.contains("password :[REDACTED]"));
    assert!(reason.contains("api_key: [REDACTED]"));
    assert!(reason.contains("Authorization: [REDACTED] [REDACTED]"));
}

#[test]
fn normalization_redacts_quoted_credential_values_containing_whitespace() {
    let input = event(
        2,
        1_723_456_789,
        "monitor",
        r#"password="kilo lima" api_key='mike november' done"#,
        "/",
    );
    let events = read_events(Cursor::new(input)).expect("valid sanitized event");
    let reason = &events[0].reason;

    for fragment in ["kilo", "lima", "mike", "november"] {
        assert!(
            !reason.contains(fragment),
            "leaked a fixture secret fragment in {reason}"
        );
    }
    assert!(reason.contains("[REDACTED]"));
    assert!(reason.ends_with("done"));
}

#[test]
fn oversized_reason_is_bounded_without_poisoning_the_batch() {
    let oversized = "signal ".repeat(400);
    let input = format!(
        "{}{}",
        event(10, 1_723_456_789, "block", &oversized, "/first"),
        event(11, 1_723_456_790, "monitor", "rule match", "/second")
    );

    let events = read_events(Cursor::new(input)).expect("oversized reason stays exportable");
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].reason.chars().count(), 2_048);
    assert!(
        events[0]
            .reason
            .ends_with("[TRUNCATED; original_chars=2800]")
    );
    assert_eq!(events[1].reason, "rule match");
}

#[test]
fn long_query_is_stripped_before_path_limit() {
    let input = event(
        12,
        1_723_456_791,
        "monitor",
        "rule match",
        &format!("/checkout?{}", "a".repeat(5_000)),
    );

    let events = read_events(Cursor::new(input)).expect("query-only overflow stays exportable");
    assert_eq!(events[0].path, "/checkout");
}

#[test]
fn oversized_route_id_is_bounded_without_poisoning_the_batch() {
    let first = serde_json::json!({
        "id": 13,
        "timestamp_unix": 1_723_456_792_u64,
        "client_ip": "203.0.113.9",
        "route_id": "r".repeat(MAX_ROUTE_ID_CHARS + 32),
        "action": "monitor",
        "reason": "rule match",
        "score": 55,
        "path": "/first"
    })
    .to_string();
    let input = format!(
        "{first}\n{}",
        event(14, 1_723_456_793, "monitor", "rule match", "/second")
    );

    let events = read_events(Cursor::new(input)).expect("oversized route ids stay exportable");
    assert_eq!(events.len(), 2);
    assert_eq!(
        events[0]
            .route_id
            .as_deref()
            .expect("route id should remain present")
            .chars()
            .count(),
        MAX_ROUTE_ID_CHARS
    );
    assert_eq!(events[1].route_id.as_deref(), Some("checkout"));
}
