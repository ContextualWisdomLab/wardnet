//! DNSBL publishing regressions for RFC 1035 section 3.3 character strings.

#[path = "support/dnsbl_txt.rs"]
mod dnsbl_txt;

use waf_ids_core::{DnsblEntry, export_dnsbl_zone, validate_dnsbl};

/// Construct a valid admission fixture without changing DNSBL classification.
fn entry(reason: String, source: String) -> DnsblEntry {
    DnsblEntry {
        address: "192.0.2.10".parse().unwrap(),
        code: "127.0.0.2".to_string(),
        reason,
        source,
        ttl_seconds: 300,
        prefix_len: None,
    }
}

/// Assert independent TXT decoding preserves the admitted reason/source bytes.
fn assert_round_trip(entry: DnsblEntry) -> Vec<Vec<u8>> {
    validate_dnsbl(&entry).unwrap();
    let expected = format!("{} source={}", entry.reason, entry.source);
    let zone = export_dnsbl_zone("dnsbl.example", &[entry]);
    assert_eq!(zone.lines().count(), 4);
    assert!(zone.contains("10.2.0.192 IN A 127.0.0.2\n"));
    dnsbl_txt::assert_zone_txt_valid(&zone);
    let text = zone
        .lines()
        .find_map(|l| l.split_once(" IN TXT ").map(|(_, t)| t))
        .unwrap();
    let strings = dnsbl_txt::decode_txt_rdata(text);
    assert_eq!(strings.concat(), expected.as_bytes());
    strings
}

#[test]
fn txt_chunking_counts_decoded_bytes_at_the_255_byte_boundary() {
    for total in [254, 255, 256, 510, 511] {
        let strings = assert_round_trip(entry("x".repeat(total - 12), "unit".to_string()));
        assert_eq!(strings.len(), total.div_ceil(255));
    }
    let strings = assert_round_trip(entry("\\\"".repeat(100), "unit".to_string()));
    assert_eq!(
        strings.len(),
        1,
        "escaped syntax is not decoded payload size"
    );
}

#[test]
fn txt_chunking_keeps_multibyte_utf8_and_escapes_lossless() {
    let reason = format!("{}한🛡\\\"\n\r\t\u{0}\u{85}", "x".repeat(254));
    let strings = assert_round_trip(entry(reason, "소스\\\"\n".repeat(90)));
    assert_eq!(strings[0].len(), 254);
    for string in strings {
        std::str::from_utf8(&string).expect("split must not bisect UTF-8");
    }
}

#[test]
fn long_admitted_txt_metadata_is_losslessly_split_into_wire_sized_strings() {
    let strings = assert_round_trip(entry("x".repeat(600), "unit".to_string()));
    assert_eq!(
        strings.iter().map(Vec::len).collect::<Vec<_>>(),
        [255, 255, 102]
    );
}
