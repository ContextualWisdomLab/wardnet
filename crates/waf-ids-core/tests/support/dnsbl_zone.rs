//! Test-only independent DNSBL publication oracle shared with the fuzz harness.

#[path = "dnsbl_txt.rs"]
pub mod dnsbl_txt;

use std::net::IpAddr;
use waf_ids_core::DnsblEntry;

/// Check the exported records against input evidence without calling production
/// validation, address reversal or lifetime projection helpers. Expected TTLs
/// use an independent linear scan per owner rather than the exporter's map.
pub fn assert_zone_matches_entries(zone: &str, entries: &[DnsblEntry]) {
    dnsbl_txt::assert_zone_txt_valid(zone);
    let expected: Vec<_> = entries
        .iter()
        .filter(|entry| {
            entry.address.is_ipv4()
                && (1..=2_147_483_647).contains(&entry.ttl_seconds)
                && matches!(entry.code.parse::<IpAddr>(), Ok(IpAddr::V4(code)) if code.octets()[0] == 127)
        })
        .collect();
    let mut lines = zone.lines();
    assert!(lines.next().unwrap().starts_with("$ORIGIN "));
    assert_eq!(lines.next(), Some("$TTL 300"));
    let mut answers = Vec::new();
    let mut texts = Vec::new();
    for line in lines {
        let (owner, record) = line
            .split_once(" IN ")
            .expect("record must contain IN class");
        let fields: Vec<_> = owner.split_whitespace().collect();
        let (name, ttl) = match fields.as_slice() {
            [name] => (*name, 300),
            [name, ttl] => (*name, ttl.parse::<u64>().expect("invalid explicit TTL")),
            _ => panic!("invalid owner/TTL fields: {owner}"),
        };
        assert!((1..=2_147_483_647).contains(&ttl));
        if let Some(code) = record.strip_prefix("A ") {
            let IpAddr::V4(code) = code.parse::<IpAddr>().expect("invalid A answer") else {
                panic!("IPv6 answer in A record");
            };
            assert_eq!(code.octets()[0], 127);
            answers.push((name, ttl, code));
        } else if let Some(text) = record.strip_prefix("TXT ") {
            texts.push((name, ttl, dnsbl_txt::decode_txt_rdata(text).concat()));
        } else {
            panic!("unexpected DNSBL record: {record}");
        }
    }
    assert_eq!(
        answers.len(),
        expected.len(),
        "A count must match input evidence"
    );
    assert_eq!(
        texts.len(),
        expected.len(),
        "TXT count must match input evidence"
    );
    for ((answer, text), entry) in answers.iter().zip(&texts).zip(&expected) {
        let IpAddr::V4(address) = entry.address else {
            unreachable!()
        };
        let [a, b, c, d] = address.octets();
        let name = format!("{d}.{c}.{b}.{a}");
        let ttl = expected
            .iter()
            .filter(|other| other.address == entry.address)
            .map(|other| other.ttl_seconds)
            .min()
            .unwrap();
        assert_eq!(answer.0, name, "A owner/order mismatch");
        assert_eq!(text.0, name, "TXT owner/order mismatch");
        assert_eq!(
            answer.1, ttl,
            "A TTL must match owner's shortest input lifetime"
        );
        assert_eq!(
            text.1, ttl,
            "TXT TTL must match owner's shortest input lifetime"
        );
        assert_eq!(IpAddr::V4(answer.2), entry.code.parse::<IpAddr>().unwrap());
        assert_eq!(
            text.2,
            format!("{} source={}", entry.reason, entry.source).as_bytes()
        );
    }
}
