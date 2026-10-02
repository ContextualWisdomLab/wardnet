//! Independent publication-oracle sensitivity, not synthetic product defects.

#[path = "support/dnsbl_zone.rs"]
mod dnsbl_zone;

use waf_ids_core::DnsblEntry;

/// Build two source records sharing an IPv4 DNS owner with different TTLs.
fn entries() -> Vec<DnsblEntry> {
    [600, 60]
        .into_iter()
        .map(|ttl_seconds| DnsblEntry {
            address: "192.0.2.10".parse().unwrap(),
            code: "127.0.0.2".into(),
            reason: "scanner".into(),
            source: "unit".into(),
            ttl_seconds,
            prefix_len: None,
        })
        .collect()
}

/// Render explicit independent fixture records rather than calling the exporter.
fn zone(ttls: [u64; 2]) -> String {
    let mut zone = "$ORIGIN dnsbl.example.\n$TTL 300\n".to_string();
    for ttl in ttls {
        zone.push_str(&format!(
            "10.2.0.192 {ttl} IN A 127.0.0.2\n10.2.0.192 {ttl} IN TXT \"scanner source=unit\"\n"
        ));
    }
    zone
}

/// Accept shared-owner minimums and implicit default TTLs as positive controls.
#[test]
fn oracle_accepts_valid_shared_owner_minimum_and_default_ttl() {
    dnsbl_zone::assert_zone_matches_entries(&zone([60, 60]), &entries());
    let mut entries = entries();
    for entry in &mut entries {
        entry.ttl_seconds = 300;
    }
    dnsbl_zone::assert_zone_matches_entries(
        &zone([300, 300]).replace(" 300 IN ", " IN "),
        &entries,
    );
}

/// Reject malformed cache lifetimes while requiring valid controls to pass.
#[test]
fn oracle_rejects_wrong_or_inconsistent_cache_lifetimes() {
    for bad in [zone([600, 60]), zone([300, 300]), zone([0, 0])] {
        assert!(
            std::panic::catch_unwind(|| {
                dnsbl_zone::assert_zone_matches_entries(&bad, &entries());
            })
            .is_err(),
            "oracle admitted incorrect TTLs: {bad}"
        );
    }
}

/// Reject missing records even when the surviving record grammar is valid.
#[test]
fn oracle_rejects_missing_answer_or_text_records() {
    for omitted in [" IN A ", " IN TXT "] {
        let bad = zone([60, 60])
            .lines()
            .filter(|line| !line.contains(omitted))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            std::panic::catch_unwind(|| {
                dnsbl_zone::assert_zone_matches_entries(&bad, &entries());
            })
            .is_err()
        );
    }
}

/// Reject otherwise-legal answer owner, response-code and metadata drift.
#[test]
fn oracle_rejects_answer_identity_and_metadata_drift() {
    for bad in [
        zone([60, 60]).replace("127.0.0.2", "127.0.0.3"),
        zone([60, 60]).replace("10.2.0.192", "11.2.0.192"),
        zone([60, 60]).replace("scanner source=unit", "other source=unit"),
    ] {
        assert!(
            std::panic::catch_unwind(|| {
                dnsbl_zone::assert_zone_matches_entries(&bad, &entries());
            })
            .is_err()
        );
    }
}
