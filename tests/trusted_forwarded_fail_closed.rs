//! Hostile regression coverage for trusted forwarding metadata.
//!
//! A trusted proxy is permitted to supply client identity only when the entire
//! `X-Forwarded-For` chain is syntactically valid. Any malformed or empty hop
//! invalidates that header as attribution evidence; Wardnet must then use the
//! direct peer rather than trusting another forwarded header.

use std::net::IpAddr;
use waf_ids_ai_soc::{IpNet, effective_client_ip};

fn ip(value: &str) -> IpAddr {
    value.parse().expect("test IP must parse")
}

fn trusted_proxy_range() -> Vec<IpNet> {
    vec![IpNet::parse("192.0.2.0/24").expect("test CIDR must parse")]
}

#[test]
fn malformed_middle_hop_falls_back_to_direct_peer() {
    let direct_peer = ip("192.0.2.44");
    let resolved = effective_client_ip(
        Some(direct_peer),
        Some("198.51.100.77, bad-ip, 192.0.2.10"),
        Some("203.0.113.99"),
        &trusted_proxy_range(),
    );

    assert_eq!(
        resolved,
        Some(direct_peer),
        "a malformed trusted forwarding chain must not select another forwarded identity"
    );
}

#[test]
fn empty_middle_hop_falls_back_to_direct_peer() {
    let direct_peer = ip("192.0.2.44");
    let resolved = effective_client_ip(
        Some(direct_peer),
        Some("198.51.100.77, , 192.0.2.10"),
        Some("203.0.113.99"),
        &trusted_proxy_range(),
    );

    assert_eq!(resolved, Some(direct_peer));
}

#[test]
fn valid_chain_still_selects_rightmost_untrusted_hop() {
    let resolved = effective_client_ip(
        Some(ip("192.0.2.44")),
        Some("198.51.100.77, 203.0.113.9, 192.0.2.10"),
        Some("203.0.113.99"),
        &trusted_proxy_range(),
    );

    assert_eq!(resolved, Some(ip("203.0.113.9")));
}

#[test]
fn absent_forwarded_chain_may_use_trusted_real_ip_fallback() {
    let resolved = effective_client_ip(
        Some(ip("192.0.2.44")),
        None,
        Some("203.0.113.99"),
        &trusted_proxy_range(),
    );

    assert_eq!(resolved, Some(ip("203.0.113.99")));
}
