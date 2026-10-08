//! Publication boundary regressions for DNS label and full-owner wire limits.

use waf_ids_core::{DnsblEntry, export_dnsbl_zone};

fn entry() -> DnsblEntry {
    DnsblEntry {
        address: "255.255.255.255".parse().unwrap(),
        code: "127.0.0.2".into(),
        reason: "scanner".into(),
        source: "unit".into(),
        ttl_seconds: 300,
        prefix_len: None,
    }
}

#[test]
fn origin_reserves_wire_space_for_the_longest_ipv4_owner() {
    // Four reversed IPv4 labels each need one length octet plus three digits.
    // These origins consume 239 and 240 wire bytes including the root octet.
    let valid = [
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(45),
    ]
    .join(".");
    let invalid = [
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(46),
    ]
    .join(".");
    assert_eq!(valid.len() + 2 + 16, 255);
    assert_eq!(invalid.len() + 2 + 16, 256);
    assert!(export_dnsbl_zone(&valid, &[entry()]).starts_with(&format!("$ORIGIN {valid}.\n")));
    let zone = export_dnsbl_zone(&invalid, &[entry()]);
    assert!(zone.starts_with("$ORIGIN dnsbl.invalid.\n"));
    assert!(zone.contains("255.255.255.255 IN A 127.0.0.2\n"));
}

#[test]
fn interior_empty_origin_label_uses_existing_nonresolving_fallback() {
    let zone = export_dnsbl_zone("dnsbl..example", &[entry()]);
    assert!(zone.starts_with("$ORIGIN dnsbl.invalid.\n"));
    assert!(zone.contains("255.255.255.255 IN A 127.0.0.2\n"));
}

#[test]
fn oversized_origin_label_uses_existing_nonresolving_fallback() {
    let valid = format!("{}.example", "a".repeat(63));
    assert!(export_dnsbl_zone(&valid, &[entry()]).starts_with(&format!("$ORIGIN {valid}.\n")));
    let invalid = format!("{}.example", "a".repeat(64));
    let zone = export_dnsbl_zone(&invalid, &[entry()]);
    assert!(zone.starts_with("$ORIGIN dnsbl.invalid.\n"));
    assert!(zone.contains("255.255.255.255 IN A 127.0.0.2\n"));
    assert!(zone.contains("255.255.255.255 IN TXT \"scanner source=unit\"\n"));
}
