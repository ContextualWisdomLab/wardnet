//! Property-based invariant tests for the untrusted-input surfaces.
//!
//! These mirror the coverage-guided cargo-fuzz targets in `../../fuzz` but run
//! on stable as part of the normal `cargo test` suite, so the same "no panic /
//! invariants hold on arbitrary input" guarantees are enforced in primary CI
//! without a nightly toolchain. The fuzz targets explore far deeper; these keep
//! a fast, always-green signal.

use proptest::prelude::*;
use std::net::{IpAddr, Ipv4Addr};
use waf_ids_core::{
    AppData, DnsblEntry, Severity, ThreatIndicator, export_dnsbl_zone, score_request,
    validate_dnsbl,
};

fn severity_strategy() -> impl Strategy<Value = Severity> {
    prop_oneof![
        Just(Severity::Low),
        Just(Severity::Medium),
        Just(Severity::High),
        Just(Severity::Critical),
    ]
}

fn threat_strategy() -> impl Strategy<Value = ThreatIndicator> {
    (".*", ".*", severity_strategy(), ".*", any::<u64>()).prop_map(
        |(value, indicator_type, severity, source, ttl_seconds)| ThreatIndicator {
            value,
            indicator_type,
            severity,
            source,
            ttl_seconds,
        },
    )
}

fn dnsbl_strategy() -> impl Strategy<Value = DnsblEntry> {
    (any::<u32>(), ".*", ".*", ".*", any::<u64>()).prop_map(
        |(addr, code, reason, source, ttl_seconds)| DnsblEntry {
            address: IpAddr::V4(Ipv4Addr::from(addr)),
            code,
            reason,
            source,
            ttl_seconds,
        },
    )
}

proptest! {
    // The core WAF scorer must never panic on arbitrary request bytes, always
    // return a non-empty reason, and score deterministically.
    #[test]
    fn score_request_never_panics_and_is_deterministic(
        path in ".*",
        query in proptest::option::of(".*"),
        body in ".*",
        client_ip in proptest::option::of(any::<u32>()),
        threats in proptest::collection::vec(threat_strategy(), 0..16),
        dnsbl in proptest::collection::vec(dnsbl_strategy(), 0..16),
    ) {
        let ip = client_ip.map(|v| IpAddr::V4(Ipv4Addr::from(v)));
        let scored = score_request(&path, query.as_deref(), &body, ip, &threats, &dnsbl);
        prop_assert!(!scored.reason.is_empty());

        let again = score_request(&path, query.as_deref(), &body, ip, &threats, &dnsbl);
        prop_assert_eq!(scored.score, again.score);
        prop_assert_eq!(scored.reason, again.reason);
    }

    // Arbitrary state-file JSON must only ever parse or error, never panic; any
    // value that parses must round-trip through serde_json.
    #[test]
    fn appdata_json_never_panics_and_round_trips(text in ".*") {
        if let Ok(parsed) = serde_json::from_str::<AppData>(&text) {
            let reserialized = serde_json::to_string(&parsed).expect("AppData re-serializes");
            let reparsed: AppData =
                serde_json::from_str(&reserialized).expect("re-serialized AppData parses");
            prop_assert_eq!(parsed, reparsed);
        }
    }

    // DNSBL classification and zone generation must never panic, and every TXT
    // payload must be fully escaped (no unescaped double quote survives).
    #[test]
    fn dnsbl_zone_generation_escapes_and_never_panics(
        origin in ".*",
        entries in proptest::collection::vec(dnsbl_strategy(), 0..32),
    ) {
        for entry in &entries {
            let _ = validate_dnsbl(entry);
        }
        let zone = export_dnsbl_zone(&origin, &entries);
        prop_assert!(zone.starts_with("$ORIGIN "));

        for line in zone.lines() {
            if !line.contains(" IN TXT ") {
                continue;
            }
            let (Some(start), Some(end)) = (line.find('"'), line.rfind('"')) else {
                continue;
            };
            if end <= start {
                continue;
            }
            let payload = &line.as_bytes()[start + 1..end];
            for (idx, &b) in payload.iter().enumerate() {
                if b == b'"' {
                    let mut backslashes = 0usize;
                    let mut j = idx;
                    while j > 0 && payload[j - 1] == b'\\' {
                        backslashes += 1;
                        j -= 1;
                    }
                    prop_assert!(backslashes % 2 == 1, "unescaped quote in TXT payload");
                }
            }
        }
    }
}
