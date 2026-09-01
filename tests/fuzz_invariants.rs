//! Property-based invariant tests mirrored from the cargo-fuzz targets.
//!
//! These run on stable in the normal `cargo test` suite so core invariants stay
//! covered in primary CI.

use proptest::prelude::*;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use waf_ids_ai_soc::{IpNet, effective_client_ip, parse_admin_tokens};

fn normalized_ip(addr: IpAddr) -> IpAddr {
    match addr {
        IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(ip)),
        IpAddr::V4(ip) => IpAddr::V4(ip),
    }
}

fn is_trusted_single_host(ip: IpAddr, trusted_proxy_ip: IpAddr) -> bool {
    normalized_ip(ip) == normalized_ip(trusted_proxy_ip)
}

proptest! {
    #[test]
    fn parse_admin_tokens_upholds_invariants(raw in ".*") {
        let tokens = parse_admin_tokens(&raw);
        for (token, principal) in &tokens {
            prop_assert!(!token.is_empty(), "token key must never be empty");
            prop_assert!(!principal.actor.is_empty(), "actor value must never be empty");
        }
    }

    #[test]
    fn trusted_forwarded_client_ip_matches_right_to_left_trust_model(
        trusted_proxy in prop_oneof![any::<u32>().prop_map(Ipv4Addr::from).prop_map(IpAddr::V4), any::<u128>().prop_map(Ipv6Addr::from).prop_map(IpAddr::V6)],
        peer_ip in prop::option::of(prop_oneof![any::<u32>().prop_map(Ipv4Addr::from).prop_map(IpAddr::V4), any::<u128>().prop_map(Ipv6Addr::from).prop_map(IpAddr::V6)]),
        trust_peer in any::<bool>(),
        forwarded_hops in prop::collection::vec(
            prop_oneof![
                any::<u32>().prop_map(Ipv4Addr::from).prop_map(IpAddr::V4).prop_map(|ip| ip.to_string()),
                any::<u128>().prop_map(Ipv6Addr::from).prop_map(IpAddr::V6).prop_map(|ip| ip.to_string()),
                ".*",
                Just(String::from(" ")),
            ],
            0..8
        ),
        x_real_ip in prop::option::of(prop_oneof![
            any::<u32>().prop_map(Ipv4Addr::from).prop_map(IpAddr::V4).prop_map(|ip| ip.to_string()),
            any::<u128>().prop_map(Ipv6Addr::from).prop_map(IpAddr::V6).prop_map(|ip| ip.to_string()),
            ".*",
            Just(String::from(" ")),
        ]),
    ) {
        let trusted_proxy_ip = trusted_proxy;
        let trusted_proxy_raw = match trusted_proxy_ip {
            IpAddr::V4(ip) => format!("{ip}/32"),
            IpAddr::V6(ip) => format!("{ip}/128"),
        };
        let trusted_proxy = IpNet::parse(&trusted_proxy_raw).unwrap();
        let trusted_proxies = vec![trusted_proxy.clone()];
        let peer_ip = if trust_peer && peer_ip.is_some() {
            Some(trusted_proxy_ip)
        } else {
            peer_ip
        };
        let trust_peer = peer_ip
            .map(|peer_ip| is_trusted_single_host(peer_ip, trusted_proxy_ip))
            .unwrap_or(false);
        let x_forwarded_for = if forwarded_hops.is_empty() {
            None
        } else {
            Some(forwarded_hops.join(","))
        };
        let resolved = effective_client_ip(
            peer_ip,
            x_forwarded_for.as_deref(),
            x_real_ip.as_deref(),
            &trusted_proxies,
        );
        let expected = peer_ip.and_then(|peer_ip| {
            if !trust_peer {
                return Some(peer_ip);
            }
            if let Some(forwarded) = x_forwarded_for.as_deref() {
                for hop in forwarded.split(',').rev() {
                    let hop = hop.trim();
                    if hop.is_empty() {
                        continue;
                    }
                    let Ok(ip) = hop.parse::<IpAddr>() else {
                        continue;
                    };
                    if is_trusted_single_host(ip, trusted_proxy_ip) {
                        continue;
                    }
                    return Some(ip);
                }
            }
            x_real_ip
                .as_deref()
                .and_then(|value| value.trim().parse::<IpAddr>().ok())
                .or(Some(peer_ip))
        });

        prop_assert_eq!(resolved, expected);
    }
}

#[test]
fn trusted_forwarded_client_ip_accepts_ipv4_mapped_trusted_peer_reference_model() {
    let trusted_proxies = vec![IpNet::parse("192.0.2.44/32").unwrap()];
    let peer_ip = Some(IpAddr::V6(Ipv4Addr::new(192, 0, 2, 44).to_ipv6_mapped()));
    let resolved = effective_client_ip(
        peer_ip,
        Some("198.51.100.7, 192.0.2.44"),
        None,
        &trusted_proxies,
    );

    assert_eq!(resolved, Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7))));
}
