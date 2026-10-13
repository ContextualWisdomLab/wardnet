//! DNSBL cache-lifetime regressions at the zone publishing boundary.

use waf_ids_core::{DnsblEntry, export_dnsbl_zone, validate_dnsbl};

/// Build an exact IPv4 entry with an independently selected cache lifetime.
fn entry(ttl_seconds: u64) -> DnsblEntry {
    DnsblEntry {
        address: "192.0.2.10".parse().unwrap(),
        code: "127.0.0.2".to_string(),
        reason: "scanner".to_string(),
        source: "unit".to_string(),
        ttl_seconds,
        prefix_len: None,
    }
}

/// Resolve explicit/default TTLs from the records actually published by Wardnet.
fn record_ttls(zone: &str) -> Vec<u64> {
    let default = zone
        .lines()
        .find_map(|line| line.strip_prefix("$TTL "))
        .unwrap()
        .parse::<u64>()
        .unwrap();
    zone.lines()
        .filter(|line| !line.starts_with('$'))
        .map(|line| {
            let fields: Vec<_> = line.split_whitespace().collect();
            if fields[1] == "IN" {
                default
            } else {
                assert_eq!(fields[2], "IN");
                fields[1].parse().unwrap()
            }
        })
        .collect()
}

#[test]
fn published_a_and_txt_records_preserve_the_admitted_ttl() {
    for ttl in [1, 60, 299, 300, 301, 86_400, 2_147_483_647] {
        let entry = entry(ttl);
        validate_dnsbl(&entry).unwrap();
        let zone = export_dnsbl_zone("dnsbl.example", &[entry]);
        assert_eq!(record_ttls(&zone), [ttl, ttl], "zone: {zone}");
    }
}

#[test]
fn ttl_outside_the_dns_wire_range_is_rejected_before_admission() {
    for ttl in [2_147_483_648, u32::MAX as u64, u64::MAX] {
        assert_eq!(
            validate_dnsbl(&entry(ttl)),
            Err("DNSBL ttl_seconds must not exceed 2147483647")
        );
    }
}

#[test]
fn invalid_persisted_ttl_cannot_make_the_published_zone_unloadable() {
    for ttl in [0, 2_147_483_648, u64::MAX] {
        let zone = export_dnsbl_zone("dnsbl.example", &[entry(ttl)]);
        assert_eq!(zone, "$ORIGIN dnsbl.example.\n$TTL 300\n");
    }
}

#[test]
fn a_shared_dns_owner_uses_the_shortest_valid_ttl_for_both_rrsets() {
    let mut short = entry(60);
    short.code = "127.0.0.3".to_string();
    short.source = "second-source".to_string();
    let mut invalid = entry(1);
    invalid.code = "8.8.8.8".to_string();
    let mut other = entry(86_400);
    other.address = "192.0.2.20".parse().unwrap();
    for entries in [
        vec![entry(600), short.clone(), invalid.clone(), other.clone()],
        vec![other, invalid, short, entry(600)],
    ] {
        let zone = export_dnsbl_zone("dnsbl.example", &entries);
        let shared: Vec<_> = zone
            .lines()
            .filter(|line| line.starts_with("10.2.0.192 "))
            .collect();
        assert_eq!(shared.len(), 4);
        assert!(
            shared
                .iter()
                .all(|line| line.starts_with("10.2.0.192 60 IN ")),
            "{zone}"
        );
        assert!(zone.contains("20.2.0.192 86400 IN A 127.0.0.2"));
        assert!(!zone.contains("8.8.8.8"));
    }
}

#[test]
fn default_300_second_zone_remains_byte_identical() {
    assert_eq!(
        export_dnsbl_zone("dnsbl.example", &[entry(300)]),
        "$ORIGIN dnsbl.example.\n$TTL 300\n10.2.0.192 IN A 127.0.0.2\n10.2.0.192 IN TXT \"scanner source=unit\"\n"
    );
}
