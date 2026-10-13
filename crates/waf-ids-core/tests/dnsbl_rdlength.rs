//! Aggregate TXT wire-size boundary without shrinking metadata silently.

use waf_ids_core::{DnsblEntry, export_dnsbl_zone, validate_dnsbl};

#[path = "support/dnsbl_txt.rs"]
mod dnsbl_txt;

fn ascii_entry(payload_bytes: usize) -> DnsblEntry {
    DnsblEntry {
        address: "192.0.2.10".parse().unwrap(),
        code: "127.0.0.2".into(),
        reason: "x".repeat(payload_bytes - 12),
        source: "unit".into(),
        ttl_seconds: 300,
        prefix_len: None,
    }
}

/// Count actual UTF-8-safe chunk length octets independently in test code.
fn wire_bytes(entry: &DnsblEntry) -> usize {
    let payload = format!("{} source={}", entry.reason, entry.source);
    let mut chunks = vec![0usize];
    for scalar in payload.chars() {
        let length = scalar.len_utf8();
        if chunks.last().unwrap() + length > 255 {
            chunks.push(0);
        }
        *chunks.last_mut().unwrap() += length;
    }
    payload.len() + chunks.len()
}

/// Stored metadata bypassing admission must not make a zone unloadable or
/// reduce a valid shared-owner RRset lifetime. Invalid evidence stays stored.
#[test]
fn oversized_persisted_metadata_is_omitted_from_both_publication_passes() {
    let mut valid = ascii_entry(65_279);
    valid.ttl_seconds = 600;
    let mut invalid = ascii_entry(65_280);
    invalid.ttl_seconds = 1;
    let entries = [valid.clone(), invalid];
    let original = entries.clone();
    let zone = export_dnsbl_zone("dnsbl.example", &entries);
    assert_eq!(entries, original);
    dnsbl_txt::assert_zone_txt_valid(&zone);
    assert_eq!(
        zone.lines().count(),
        4,
        "only the publishable entry remains"
    );
    assert!(zone.contains("10.2.0.192 600 IN A 127.0.0.2\n"));
    let text = zone
        .lines()
        .find_map(|line| line.split_once(" IN TXT "))
        .unwrap()
        .1;
    let chunks = dnsbl_txt::decode_txt_rdata(text);
    assert_eq!(
        chunks.iter().map(|chunk| 1 + chunk.len()).sum::<usize>(),
        65_535
    );
    assert_eq!(
        chunks.concat(),
        format!("{} source={}", valid.reason, valid.source).as_bytes()
    );
    let reversed = [entries[1].clone(), entries[0].clone()];
    assert_eq!(export_dnsbl_zone("dnsbl.example", &reversed), zone);
}

/// UTF-8 boundaries add length octets even when an ASCII payload of the same
/// byte length would fit. Escaped master-file spelling is not RDATA length.
#[test]
fn utf8_chunk_overhead_and_escaped_bytes_use_actual_wire_lengths() {
    let mut valid = ascii_entry(12);
    valid.reason = "😀".repeat(16_315);
    let mut invalid = valid.clone();
    invalid.reason.push('😀');
    assert_eq!(wire_bytes(&valid), 65_532);
    assert_eq!(wire_bytes(&invalid), 65_536);
    assert_eq!(validate_dnsbl(&valid), Ok(()));
    assert!(validate_dnsbl(&invalid).is_err());
    let zone = export_dnsbl_zone("dnsbl.example", &[valid.clone(), invalid]);
    assert_eq!(zone.lines().count(), 4);
    dnsbl_txt::assert_zone_txt_valid(&zone);
    let decoded = dnsbl_txt::decode_txt_rdata(
        zone.lines()
            .last()
            .unwrap()
            .split_once(" IN TXT ")
            .unwrap()
            .1,
    )
    .concat();
    assert_eq!(
        decoded,
        format!("{} source={}", valid.reason, valid.source).as_bytes()
    );
    for scalar in ['"', '\\', '\n', '\0'] {
        let mut escaped = ascii_entry(65_279);
        escaped.reason = format!("x{}", scalar.to_string().repeat(65_266));
        assert_eq!(validate_dnsbl(&escaped), Ok(()));
        let zone = export_dnsbl_zone("dnsbl.example", &[escaped.clone()]);
        dnsbl_txt::assert_zone_txt_valid(&zone);
        let text = zone
            .lines()
            .last()
            .unwrap()
            .split_once(" IN TXT ")
            .unwrap()
            .1;
        let chunks = dnsbl_txt::decode_txt_rdata(text);
        assert_eq!(
            chunks.iter().map(|chunk| 1 + chunk.len()).sum::<usize>(),
            65_535
        );
        assert_eq!(
            chunks.concat(),
            format!("{} source={}", escaped.reason, escaped.source).as_bytes()
        );
    }
}

#[test]
fn admission_bounds_total_txt_rdata_including_chunk_length_octets() {
    let valid = ascii_entry(65_279);
    let invalid = ascii_entry(65_280);
    assert_eq!(wire_bytes(&valid), 65_535);
    assert_eq!(wire_bytes(&invalid), 65_536);
    assert_eq!(validate_dnsbl(&valid), Ok(()));
    assert_eq!(
        validate_dnsbl(&invalid),
        Err("DNSBL TXT metadata exceeds 65535 wire bytes")
    );
}
