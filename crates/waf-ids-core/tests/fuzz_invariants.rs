//! Property-based invariant tests for the untrusted-input surfaces.
//!
//! These mirror the coverage-guided cargo-fuzz targets in `../../fuzz` but run
//! on stable as part of the normal `cargo test` suite, so the same "no panic /
//! invariants hold on arbitrary input" guarantees are enforced in primary CI
//! without a nightly toolchain. The fuzz targets explore far deeper; these keep
//! a fast, always-green signal.

#[path = "support/dnsbl_txt.rs"]
mod dnsbl_txt;

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

// Response codes cover arbitrary strings plus real IP literals (loopback,
// non-loopback IPv4, and IPv6) so the zone-export A-record invariant below is
// actually exercised — a purely random string almost never parses as an IP.
fn dnsbl_code_strategy() -> impl Strategy<Value = String> {
    prop_oneof![
        ".*",
        any::<u32>().prop_map(|v| Ipv4Addr::from(v).to_string()),
        (any::<u8>(), any::<u8>(), any::<u8>()).prop_map(|(a, b, c)| format!("127.{a}.{b}.{c}")),
        any::<u128>().prop_map(|v| std::net::Ipv6Addr::from(v).to_string()),
    ]
}

fn dnsbl_strategy() -> impl Strategy<Value = DnsblEntry> {
    (
        any::<u32>(),
        dnsbl_code_strategy(),
        ".*",
        ".*",
        prop_oneof![any::<u64>(), 1u64..=2_147_483_647, Just(0), Just(300)],
    )
        .prop_map(|(addr, code, reason, source, ttl_seconds)| DnsblEntry {
            address: IpAddr::V4(Ipv4Addr::from(addr)),
            code,
            reason,
            source,
            ttl_seconds,
            prefix_len: None,
        })
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

    // DNSBL classification and zone generation must never panic; TXT payloads
    // must retain valid escaped strings and legal adjacent-string delimiters.
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

        // Parse optional explicit TTL before class/type so TXT content cannot
        // masquerade as an A record. Both record forms keep the 127/8 check.
        for line in zone.lines() {
            let fields: Vec<_> = line.split_whitespace().collect();
            let record = match fields.as_slice() {
                [_name, "IN", "A", code] => Some((300, *code)),
                [_name, ttl, "IN", "A", code] => Some((ttl.parse::<u64>().unwrap(), *code)),
                _ => None,
            };
            let Some((ttl, code)) = record else { continue };
            prop_assert!((1..=2_147_483_647).contains(&ttl));
            match code.parse::<IpAddr>() {
                Ok(IpAddr::V4(v4)) => {
                    prop_assert_eq!(v4.octets()[0], 127, "non-loopback A code: {}", code)
                }
                other => prop_assert!(false, "illegal DNSBL A-record code: {:?}", other),
            }
        }

        dnsbl_txt::assert_zone_txt_valid(&zone);
        let txt_lines: Vec<_> = zone.lines().filter_map(|l| l.split_once(" IN TXT ")).collect();
        let expected: Vec<_> = entries.iter().filter(|e| {
            (1..=2_147_483_647).contains(&e.ttl_seconds)
                && matches!(e.code.parse::<IpAddr>(), Ok(IpAddr::V4(ip)) if ip.octets()[0] == 127)
        }).collect();
        prop_assert_eq!(txt_lines.len(), expected.len());
        for ((_, text), entry) in txt_lines.iter().zip(expected) {
            let decoded = dnsbl_txt::decode_txt_rdata(text).concat();
            prop_assert_eq!(decoded, format!("{} source={}", entry.reason, entry.source).into_bytes());
        }
    }
}
