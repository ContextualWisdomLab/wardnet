#![no_main]
//! Fuzz DNSBL validation and zone-file generation.
//!
//! `export_dnsbl_zone` renders operator/threat-feed-supplied DNSBL entries into
//! a BIND zone file, escaping the reason/source strings into TXT records. This
//! is an injection-sensitive surface: arbitrary `reason`/`source`/`code`/origin
//! strings flow into the generated zone. Generation must never panic, and
//! `validate_dnsbl` must never panic while classifying arbitrary entries.
//!
//! Invariant: every TXT record consists of valid escaped quoted strings with
//! at most 255 decoded bytes each; concatenation preserves reason/source bytes.
//! Quotes, backslashes and control characters cannot break out into zone lines.

#[path = "../support/dnsbl_txt.rs"]
mod dnsbl_txt;

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use waf_ids_core::{DnsblEntry, export_dnsbl_zone, validate_dnsbl};

/// A response code drawn from the raw fuzz bytes: arbitrary strings plus real IP
/// literals (loopback, non-loopback IPv4, IPv6) so the zone A-record invariant
/// below is exercised — a random string almost never parses as an IP.
#[derive(Arbitrary, Debug)]
enum Code {
    Raw(String),
    V4(u32),
    Loopback(u8, u8, u8),
    V6(u128),
}

impl Code {
    fn into_string(self) -> String {
        match self {
            Code::Raw(s) => s,
            Code::V4(v) => Ipv4Addr::from(v).to_string(),
            Code::Loopback(a, b, c) => format!("127.{a}.{b}.{c}"),
            Code::V6(v) => Ipv6Addr::from(v).to_string(),
        }
    }
}

#[derive(Arbitrary, Debug)]
struct Entry {
    addr: u32,
    code: Code,
    reason: String,
    source: String,
    ttl: u64,
}

#[derive(Arbitrary, Debug)]
struct Input {
    origin: String,
    entries: Vec<Entry>,
}

fuzz_target!(|input: Input| {
    let entries: Vec<DnsblEntry> = input
        .entries
        .into_iter()
        .take(64)
        .map(|e| DnsblEntry {
            address: IpAddr::V4(Ipv4Addr::from(e.addr)),
            code: e.code.into_string(),
            reason: e.reason,
            source: e.source,
            ttl_seconds: e.ttl,
            prefix_len: None,
        })
        .collect();

    // Classifying arbitrary entries must never panic.
    for entry in &entries {
        let _ = validate_dnsbl(entry);
    }

    // Zone generation must never panic on arbitrary strings.
    let zone = export_dnsbl_zone(&input.origin, &entries);

    // The zone always carries its header directive.
    assert!(
        zone.starts_with("$ORIGIN "),
        "zone must start with $ORIGIN directive"
    );

    // Every published A-record response code is an IPv4 loopback literal
    // (RFC 5782 / the "response code in 127.0.0.0/8" invariant). Codes outside
    // 127/8, IPv6 literals, and unparseable strings must all be dropped. Parse
    // by record structure from the start of the line: an A record is exactly
    // `<name> IN A <code>` (four whitespace fields, no spaces in name or code).
    // Matching on the substring " IN A " instead would misread a TXT line whose
    // escaped reason/source payload merely contains that substring as an A-record.
    for line in zone.lines() {
        let mut fields = line.split_whitespace();
        let (Some(_name), Some("IN"), Some("A"), Some(code), None) = (
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
        ) else {
            continue;
        };
        match code.parse::<IpAddr>() {
            Ok(IpAddr::V4(v4)) => assert_eq!(
                v4.octets()[0],
                127,
                "non-loopback DNSBL A-record code emitted: {code}"
            ),
            other => panic!("illegal DNSBL A-record code emitted: {other:?}"),
        }
    }

    // Check every string, including chunk separators, with an independent
    // decoder; require both wire-size legality and lossless metadata bytes.
    dnsbl_txt::assert_zone_txt_valid(&zone);
    let txt_lines: Vec<_> = zone
        .lines()
        .filter_map(|l| l.split_once(" IN TXT "))
        .collect();
    let expected: Vec<_> = entries
        .iter()
        .filter(|e| matches!(e.code.parse::<IpAddr>(), Ok(IpAddr::V4(ip)) if ip.octets()[0] == 127))
        .collect();
    assert_eq!(txt_lines.len(), expected.len());
    for ((_, text), entry) in txt_lines.iter().zip(expected) {
        assert_eq!(
            dnsbl_txt::decode_txt_rdata(text).concat(),
            format!("{} source={}", entry.reason, entry.source).into_bytes()
        );
    }
});
