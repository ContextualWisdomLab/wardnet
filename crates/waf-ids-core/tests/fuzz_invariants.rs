//! Property-based invariant tests for the untrusted-input surfaces.
//!
//! These mirror the coverage-guided cargo-fuzz targets in `../../fuzz` but run
//! on stable as part of the normal `cargo test` suite, so the same "no panic /
//! invariants hold on arbitrary input" guarantees are enforced in primary CI
//! without a nightly toolchain. The fuzz targets explore far deeper; these keep
//! a fast, always-green signal.

#[path = "support/dnsbl_zone.rs"]
mod dnsbl_zone;

use dnsbl_zone::dnsbl_txt;

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

    // Unlike the broad mixed-input property below, force 2..8 publishable
    // records to share one owner, with independently varied positive TTLs and
    // metadata. The test-only oracle independently checks minimum-per-owner TTL,
    // A/TXT parity, record identity/order, and lossless reason/source bytes.
    #[test]
    fn dnsbl_zone_preserves_shared_owner_source_metadata_and_minimum_ttl(
        address in any::<u32>(),
        records in proptest::collection::vec((
            1u64..=2_147_483_647,
            ".{0,600}",
            ".{0,120}",
        ), 2..8),
    ) {
        let address = IpAddr::V4(Ipv4Addr::from(address));
        let entries: Vec<_> = records
            .into_iter()
            .enumerate()
            .map(|(index, (ttl_seconds, reason, source))| DnsblEntry {
                address,
                code: format!("127.0.0.{}", index + 1),
                reason,
                source,
                ttl_seconds,
                prefix_len: None,
            })
            .collect();
        let original = entries.clone();
        let zone = export_dnsbl_zone("dnsbl.example", &entries);
        dnsbl_zone::assert_zone_matches_entries(&zone, &entries);
        prop_assert_eq!(entries, original, "export must not mutate source-owned entries");
    }

    // Force aggregate RDATA boundary cases as well as the short arbitrary-input
    // path. A low-TTL oversized sibling must not influence the valid owner.
    #[test]
    fn dnsbl_rdata_boundary_preserves_valid_shared_owner_projection(
        address in any::<u32>(),
        payload_bytes in 65_270usize..65_290,
        scalar in prop::sample::select(vec!['x', '😀', '\n', '"', '\\']),
    ) {
        let mut entry = DnsblEntry {
            address: IpAddr::V4(Ipv4Addr::from(address)),
            code: "127.0.0.2".into(),
            reason: format!("x{}", scalar.to_string().repeat((payload_bytes - 13) / scalar.len_utf8())),
            source: "unit".into(),
            ttl_seconds: 1,
            prefix_len: None,
        };
        let mut valid = entry.clone();
        valid.reason = "short-positive".into();
        valid.ttl_seconds = 600;
        // Metadata is nonblank, so admission must agree with the input oracle.
        prop_assert_eq!(validate_dnsbl(&entry).is_ok(), dnsbl_zone::metadata_fits_rdata(&entry));
        let zone = export_dnsbl_zone("dnsbl.example", &[valid.clone(), entry.clone()]);
        dnsbl_zone::assert_zone_matches_entries(&zone, &[valid.clone(), entry.clone()]);
        entry.reason.push(scalar);
        let zone = export_dnsbl_zone("dnsbl.example", &[entry.clone(), valid.clone()]);
        dnsbl_zone::assert_zone_matches_entries(&zone, &[entry, valid]);
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
        dnsbl_zone::assert_zone_matches_entries(&zone, &entries);

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
                && dnsbl_zone::metadata_fits_rdata(e)
                && matches!(e.code.parse::<IpAddr>(), Ok(IpAddr::V4(ip)) if ip.octets()[0] == 127)
        }).collect();
        prop_assert_eq!(txt_lines.len(), expected.len());
        for ((_, text), entry) in txt_lines.iter().zip(expected) {
            let decoded = dnsbl_txt::decode_txt_rdata(text).concat();
            prop_assert_eq!(decoded, format!("{} source={}", entry.reason, entry.source).into_bytes());
        }
    }
}
