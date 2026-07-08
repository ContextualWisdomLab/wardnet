#![no_main]
//! Fuzz DNSBL validation and zone-file generation.
//!
//! `export_dnsbl_zone` renders operator/threat-feed-supplied DNSBL entries into
//! a BIND zone file, escaping the reason/source strings into TXT records. This
//! is an injection-sensitive surface: arbitrary `reason`/`source`/`code`/origin
//! strings flow into the generated zone. Generation must never panic, and
//! `validate_dnsbl` must never panic while classifying arbitrary entries.
//!
//! Invariant: every TXT record payload is fully escaped — inside the quoted
//! payload every `"` is backslash-escaped, so the zone can never be broken out
//! of by adversarial reason/source strings.

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::net::{IpAddr, Ipv4Addr};
use waf_ids_core::{export_dnsbl_zone, validate_dnsbl, DnsblEntry};

#[derive(Arbitrary, Debug)]
struct Entry {
    addr: u32,
    code: String,
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
            code: e.code,
            reason: e.reason,
            source: e.source,
            ttl_seconds: e.ttl,
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

    // Every TXT record payload must be properly escaped: inside the wrapping
    // quotes, each `"` must be backslash-escaped. Extract the payload between
    // the first and last quote of each TXT line and verify no *unescaped* quote
    // survives (a quote is escaped iff preceded by an odd run of backslashes).
    for line in zone.lines() {
        if !line.contains(" IN TXT ") {
            continue;
        }
        let first = line.find('"');
        let last = line.rfind('"');
        if let (Some(start), Some(end)) = (first, last) {
            if end <= start {
                continue;
            }
            let bytes = &line.as_bytes()[start + 1..end];
            for (idx, &b) in bytes.iter().enumerate() {
                if b == b'"' {
                    let mut backslashes = 0usize;
                    let mut j = idx;
                    while j > 0 && bytes[j - 1] == b'\\' {
                        backslashes += 1;
                        j -= 1;
                    }
                    assert!(
                        backslashes % 2 == 1,
                        "unescaped quote in TXT payload: {line:?}"
                    );
                }
            }
        }
    }
});
