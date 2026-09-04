//! Hostile regression coverage for trusted forwarding metadata.
//!
//! A trusted proxy may supply client identity only when the entire
//! `X-Forwarded-For` chain parses cleanly. Any malformed hop invalidates the
//! header as attribution evidence, and Wardnet must fall back to the direct
//! peer without trusting `X-Real-IP`.

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

    assert_eq!(resolved, Some(direct_peer));
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
fn valid_chain_selects_rightmost_untrusted_hop() {
    let resolved = effective_client_ip(
        Some(ip("192.0.2.44")),
        Some("198.51.100.77, 203.0.113.9, 192.0.2.10"),
        Some("203.0.113.99"),
        &trusted_proxy_range(),
    );

    assert_eq!(resolved, Some(ip("203.0.113.9")));
}

#[test]
fn ipv4_mapped_cidr_configuration_is_canonicalized() {
    let mapped =
        IpNet::parse("::ffff:192.0.2.0/120").expect("mapped IPv6 CIDR should canonicalize");
    let canonical = IpNet::parse("192.0.2.0/24").expect("canonical IPv4 CIDR should parse");

    assert_eq!(mapped, canonical);
}

#[test]
fn out_of_range_ipv6_prefixes_fail_closed() {
    for value in ["2001:db8::/129", "::ffff:192.0.2.77/129"] {
        let error = IpNet::parse(value)
            .expect_err("an IPv6 prefix above 128 must not be silently reinterpreted");
        assert!(
            error.contains("prefix 129 is too large"),
            "unexpected error for {value}: {error}"
        );
    }
}
