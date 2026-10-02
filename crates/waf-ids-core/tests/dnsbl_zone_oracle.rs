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

/// Reject unparseable origins with otherwise-valid records and metadata.
#[test]
fn oracle_rejects_unparseable_origin_names() {
    // A 237-character origin plus the longest IPv4 owner fits exactly.
    let valid_origin = [
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(45),
    ]
    .join(".");
    dnsbl_zone::assert_zone_matches_entries(
        &zone([60, 60]).replace("dnsbl.example.", &format!("{valid_origin}.")),
        &entries(),
    );
    for origin in [
        format!("{}.example", "a".repeat(64)),
        "dnsbl..example".into(),
        [
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(46),
        ]
        .join("."),
    ] {
        let bad = zone([60, 60]).replace("dnsbl.example.", &format!("{origin}."));
        assert!(
            std::panic::catch_unwind(|| {
                dnsbl_zone::assert_zone_matches_entries(&bad, &entries());
            })
            .is_err(),
            "oracle admitted invalid origin: {origin}"
        );
    }
}

/// Accept a maximum-size TXT record, but reject aggregate RDATA overflow even
/// when every constituent character string remains legal.
#[test]
fn oracle_bounds_total_txt_rdata_and_omits_unpublishable_input() {
    let mut entry = entries().remove(0);
    entry.ttl_seconds = 300;
    entry.reason = "x".repeat(65_267);
    let full = format!("\"{}\"", "x".repeat(255));
    let valid_text = format!(
        "{} \"{} source=unit\"",
        vec![full.clone(); 255].join(" "),
        "x".repeat(242)
    );
    let valid_zone = format!(
        "$ORIGIN dnsbl.example.\n$TTL 300\n10.2.0.192 IN A 127.0.0.2\n10.2.0.192 IN TXT {valid_text}\n"
    );
    dnsbl_zone::assert_zone_matches_entries(&valid_zone, &[entry.clone()]);
    let invalid_text = vec![full; 256].join(" ");
    let invalid_zone = valid_zone.replace(&valid_text, &invalid_text);
    assert!(
        std::panic::catch_unwind(|| {
            dnsbl_zone::dnsbl_txt::assert_zone_txt_valid(&invalid_zone);
        })
        .is_err(),
        "oracle accepted 65536 RDATA octets"
    );
    let mut invalid = entry.clone();
    invalid.reason.push('x');
    invalid.ttl_seconds = 1;
    dnsbl_zone::assert_zone_matches_entries(&valid_zone, &[entry, invalid]);
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
