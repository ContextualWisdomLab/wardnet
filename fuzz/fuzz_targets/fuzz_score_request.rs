#![no_main]
//! Fuzz the core WAF request scorer: `waf_ids_core::score_request`.
//!
//! This is the primary untrusted-input surface (surfaced via CodeGraph:
//! `codegraph_explore "score_request anomaly_signal normalize decode ..."`).
//! It percent-decodes the query string, lowercases a `path?query body`
//! haystack, and matches it against built-in signatures, operator threat
//! indicators, DNSBL reputation, and an anomaly heuristic — all on attacker
//! controlled bytes.
//!
//! Invariants asserted:
//!   * scoring never panics on arbitrary input (the whole point of a WAF);
//!   * the returned `reason` is never empty;
//!   * scoring is deterministic (same input => same score and reason).

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::net::{IpAddr, Ipv4Addr};
use waf_ids_core::{score_request, DnsblEntry, Severity, ThreatIndicator};

#[derive(Arbitrary, Debug)]
struct Indicator {
    value: String,
    indicator_type: String,
    severity: u8,
    source: String,
    ttl: u64,
}

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
    path: String,
    query: Option<String>,
    body: String,
    client_ip: Option<u32>,
    threats: Vec<Indicator>,
    dnsbl: Vec<Entry>,
}

fn severity(byte: u8) -> Severity {
    match byte % 4 {
        0 => Severity::Low,
        1 => Severity::Medium,
        2 => Severity::High,
        _ => Severity::Critical,
    }
}

fuzz_target!(|input: Input| {
    // Cap collection sizes so the fuzzer explores parsing/matching logic rather
    // than trivially overflowing the u16 score accumulator with thousands of
    // matching indicators (that would be an arithmetic DoS artifact, not a
    // parser bug). 32 is plenty to exercise the multi-indicator paths.
    let threats: Vec<ThreatIndicator> = input
        .threats
        .into_iter()
        .take(32)
        .map(|i| ThreatIndicator {
            value: i.value,
            indicator_type: i.indicator_type,
            severity: severity(i.severity),
            source: i.source,
            ttl_seconds: i.ttl,
        })
        .collect();

    let dnsbl: Vec<DnsblEntry> = input
        .dnsbl
        .into_iter()
        .take(32)
        .map(|e| DnsblEntry {
            address: IpAddr::V4(Ipv4Addr::from(e.addr)),
            code: e.code,
            reason: e.reason,
            source: e.source,
            ttl_seconds: e.ttl,
        })
        .collect();

    let client_ip = input.client_ip.map(|v| IpAddr::V4(Ipv4Addr::from(v)));

    let scored = score_request(
        &input.path,
        input.query.as_deref(),
        &input.body,
        client_ip,
        &threats,
        &dnsbl,
    );

    assert!(!scored.reason.is_empty(), "reason must never be empty");

    let again = score_request(
        &input.path,
        input.query.as_deref(),
        &input.body,
        client_ip,
        &threats,
        &dnsbl,
    );
    assert_eq!(scored.score, again.score, "scoring must be deterministic");
    assert_eq!(scored.reason, again.reason, "reason must be deterministic");
});
