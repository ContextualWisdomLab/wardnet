#![no_main]
//! Fuzz trusted client-IP attribution for forwarded proxy headers.
//!
//! `effective_client_ip` is a trust-boundary parser: it decides whether
//! attacker-controlled forwarding headers can influence rate limiting, DNSBL
//! checks, and audit/event attribution. Arbitrary chains, invalid hops, IPv4,
//! IPv6, trusted peers, and untrusted peers must never panic. Trusted peers may
//! supply an `X-Forwarded-For` identity only when every hop parses; malformed
//! chains fail closed to the direct peer.

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use waf_ids_ai_soc::{IpNet, effective_client_ip};

#[derive(Arbitrary, Debug, Clone)]
enum AnyIp {
    V4(u32),
    V6(u128),
}

impl AnyIp {
    fn into_ip(self) -> IpAddr {
        match self {
            Self::V4(raw) => IpAddr::V4(Ipv4Addr::from(raw)),
            Self::V6(raw) => IpAddr::V6(Ipv6Addr::from(raw)),
        }
    }
}

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

#[derive(Arbitrary, Debug)]
enum Hop {
    Ip(AnyIp),
    Invalid(String),
    Empty,
}

impl Hop {
    fn into_text(self) -> String {
        match self {
            Self::Ip(ip) => ip.into_ip().to_string(),
            Self::Invalid(raw) => raw,
            Self::Empty => " ".to_string(),
        }
    }
}

#[derive(Arbitrary, Debug)]
struct Input {
    trusted_proxy: AnyIp,
    peer_ip: Option<AnyIp>,
    trust_peer: bool,
    forwarded_hops: Vec<Hop>,
    x_real_ip: Option<Hop>,
}

fn expected_client_ip(
    peer_ip: Option<IpAddr>,
    x_forwarded_for: Option<&str>,
    x_real_ip: Option<&str>,
    trusted_proxy_ip: IpAddr,
    trust_peer: bool,
) -> Option<IpAddr> {
    let peer_ip = match (peer_ip, trust_peer) {
        (Some(_), false) => peer_ip,
        (Some(peer_ip), true) => Some(peer_ip),
        (None, _) => return None,
    }?;

    if !trust_peer {
        return Some(peer_ip);
    }

    if let Some(forwarded) = x_forwarded_for {
        let parsed = forwarded
            .split(',')
            .map(|hop| {
                let hop = hop.trim();
                if hop.is_empty() {
                    return Err(());
                }
                hop.parse::<IpAddr>().map_err(|_| ())
            })
            .collect::<Result<Vec<_>, _>>();
        let Ok(hops) = parsed else {
            return Some(peer_ip);
        };
        if let Some(client_ip) = hops
            .into_iter()
            .rev()
            .find(|ip| !is_trusted_single_host(*ip, trusted_proxy_ip))
        {
            return Some(client_ip);
        }
    }

    x_real_ip
        .and_then(|value| value.trim().parse::<IpAddr>().ok())
        .or(Some(peer_ip))
}

fuzz_target!(|input: Input| {
    let trusted_proxy_ip = input.trusted_proxy.clone().into_ip();
    let peer_ip = input.peer_ip.map(AnyIp::into_ip);
    let trusted_cidr = match trusted_proxy_ip {
        IpAddr::V4(ip) => format!("{ip}/32"),
        IpAddr::V6(ip) => format!("{ip}/128"),
    };
    let trusted_proxy = IpNet::parse(&trusted_cidr).expect("single-host CIDR must parse");
    let trusted_proxies = vec![trusted_proxy.clone()];
    let peer_ip = if input.trust_peer && peer_ip.is_some() {
        Some(trusted_proxy_ip)
    } else {
        peer_ip
    };
    let trust_peer = peer_ip
        .map(|peer_ip| is_trusted_single_host(peer_ip, trusted_proxy_ip))
        .unwrap_or(false);
    let x_forwarded_for = if input.forwarded_hops.is_empty() {
        None
    } else {
        Some(
            input
                .forwarded_hops
                .into_iter()
                .map(Hop::into_text)
                .collect::<Vec<_>>()
                .join(","),
        )
    };
    let x_real_ip = input.x_real_ip.map(Hop::into_text);
    let resolved = effective_client_ip(
        peer_ip,
        x_forwarded_for.as_deref(),
        x_real_ip.as_deref(),
        &trusted_proxies,
    );
    let expected = expected_client_ip(
        peer_ip,
        x_forwarded_for.as_deref(),
        x_real_ip.as_deref(),
        trusted_proxy_ip,
        trust_peer,
    );
    assert_eq!(
        resolved, expected,
        "trusted client attribution must fail closed on malformed forwarding metadata"
    );
});
