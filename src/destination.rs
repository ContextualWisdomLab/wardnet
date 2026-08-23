//! Fail-closed destination policy for every outbound URL (issue #79).
//!
//! One checker is used for gateway upstreams, threat-intel fetches, Clearfolio,
//! and SOC-LLM calls. Structural URL parse happens first; DNS answers are then
//! classified. Deny-overrides win over allowlists. Loopback-class destinations
//! are allowed only when [`DestinationPolicy::development`] is selected (the
//! process itself is loopback-only).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};
use waf_ids_core::ip_in_network;

/// Outcome of a destination-policy check. `reason` never includes credentials
/// or query strings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DestinationDecision {
    pub allowed: bool,
    pub reason: String,
    pub host: String,
    pub ips: Vec<IpAddr>,
}

/// Hostname, suffix, or CIDR entry parsed from an operator allow/deny list.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ListEntry {
    Hostname(String),
    Suffix(String),
    Cidr { network: IpAddr, prefix_len: u8 },
}

/// Fail-closed policy applied to outbound http/https URLs.
#[derive(Debug, Clone)]
pub struct DestinationPolicy {
    /// When true, loopback destinations are an allowed class (local development).
    allow_loopback_class: bool,
    allow: Vec<ListEntry>,
    deny: Vec<ListEntry>,
}

impl DestinationPolicy {
    /// Production default: deny loopback, private, link-local, metadata, and
    /// other non-global unicast classes unless an allowlist entry matches.
    pub fn production() -> Self {
        Self {
            allow_loopback_class: false,
            allow: Vec::new(),
            deny: Vec::new(),
        }
    }

    /// Loopback-listener development: same denies except loopback-class IPs
    /// and `localhost` are permitted so in-process fixtures can run.
    pub fn development() -> Self {
        Self {
            allow_loopback_class: true,
            allow: Vec::new(),
            deny: Vec::new(),
        }
    }

    /// Parse comma-separated allow/deny lists (`host`, `*.suffix`, `cidr`).
    pub fn with_lists(mut self, allow: &str, deny: &str) -> Result<Self, String> {
        self.allow = parse_list(allow)?;
        self.deny = parse_list(deny)?;
        Ok(self)
    }

    /// Evaluate `raw` with `resolver`. Denied destinations return `Err`.
    pub fn evaluate(
        &self,
        raw: &str,
        resolver: &dyn HostResolver,
    ) -> Result<DestinationDecision, String> {
        let parsed = parse_outbound_url(raw)?;
        let host_allowlisted = self.allow.iter().any(|entry| match entry {
            ListEntry::Hostname(_) | ListEntry::Suffix(_) => {
                matching_host(entry, &parsed.host, &[])
            }
            ListEntry::Cidr { .. } => false,
        });
        let literal_loopback = parsed.host == "localhost"
            || parsed
                .host
                .parse::<IpAddr>()
                .map(|ip| canonicalize_ip(ip).is_loopback())
                .unwrap_or(false);
        if parsed.port != 80
            && parsed.port != 443
            && !host_allowlisted
            && !(self.allow_loopback_class && literal_loopback)
        {
            return Err(format!(
                "destination port {} is not a default http/https port",
                parsed.port
            ));
        }
        let mut ips = Vec::new();
        if parsed.host == "localhost" {
            ips.push(IpAddr::V4(Ipv4Addr::LOCALHOST));
        } else if let Ok(ip) = parsed.host.parse::<IpAddr>() {
            ips.push(canonicalize_ip(ip));
        } else {
            ips = resolver
                .resolve(&parsed.host)
                .map_err(|error| format!("destination DNS failed for {}: {error}", parsed.host))?;
            if ips.is_empty() {
                return Err(format!(
                    "destination {} resolved to no addresses",
                    parsed.host
                ));
            }
            ips = ips.into_iter().map(canonicalize_ip).collect();
        }

        if let Some(entry) = self.matching_entry(&self.deny, &parsed.host, &ips) {
            return Err(format!(
                "destination {} denied by denylist ({})",
                parsed.host,
                entry_label(entry)
            ));
        }

        let allowlisted = self
            .matching_entry(&self.allow, &parsed.host, &ips)
            .is_some();

        for ip in &ips {
            if ip_is_denied_class(*ip) {
                if allowlisted || (self.allow_loopback_class && ip.is_loopback()) {
                    continue;
                }
                return Err(format!(
                    "destination {} resolved to denied address class {ip}",
                    parsed.host
                ));
            }
        }

        Ok(DestinationDecision {
            allowed: true,
            reason: format!("destination {} permitted", parsed.host),
            host: parsed.host,
            ips,
        })
    }
}

struct ParsedOutbound {
    host: String,
    port: u16,
}

/// Resolve a hostname to A/AAAA addresses. Tests inject a fake.
pub trait HostResolver {
    fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, String>;
}

/// Operating-system DNS via [`ToSocketAddrs`].
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemHostResolver;

impl HostResolver for SystemHostResolver {
    fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, String> {
        let addrs = (host, 0)
            .to_socket_addrs()
            .map_err(|error| error.to_string())?;
        let mut ips = Vec::new();
        for addr in addrs {
            let ip = canonicalize_ip(addr.ip());
            if !ips.contains(&ip) {
                ips.push(ip);
            }
        }
        Ok(ips)
    }
}

fn parse_outbound_url(raw: &str) -> Result<ParsedOutbound, String> {
    let parsed = reqwest::Url::parse(raw).map_err(|_| "destination URL must be absolute")?;
    match parsed.scheme() {
        "http" | "https" => {}
        other => {
            return Err(format!("destination scheme {other} is not http or https"));
        }
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err("destination URL must not contain userinfo".to_string());
    }
    if parsed.fragment().is_some() {
        return Err("destination URL must not contain a fragment".to_string());
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| "destination URL host is required".to_string())?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if host.is_empty() || host == "." {
        return Err("destination URL host is ambiguous".to_string());
    }
    if host_is_ambiguous_literal(host) {
        return Err(format!(
            "destination host {host} uses a forbidden numeric spelling"
        ));
    }
    let port = parsed.port_or_known_default().unwrap_or(0);
    Ok(ParsedOutbound {
        host: host.trim_end_matches('.').to_ascii_lowercase(),
        port,
    })
}

fn host_is_ambiguous_literal(host: &str) -> bool {
    if host.chars().all(|c| c.is_ascii_digit()) {
        return true;
    }
    let lowered = host.to_ascii_lowercase();
    if lowered.contains("0x") {
        return true;
    }
    let octets: Vec<&str> = host.split('.').collect();
    octets.len() == 4
        && octets
            .iter()
            .all(|octet| !octet.is_empty() && octet.chars().all(|c| c.is_ascii_digit()))
        && octets
            .iter()
            .any(|octet| octet.len() > 1 && octet.starts_with('0'))
}

fn canonicalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        IpAddr::V4(_) => ip,
    }
}

fn ip_is_denied_class(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_unspecified()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.is_documentation()
                || v4.octets()[0] == 0
                || is_metadata_v4(v4)
                || ip_in_network(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 0)), 10, ip)
                || ip_in_network(IpAddr::V4(Ipv4Addr::new(198, 18, 0, 0)), 15, ip)
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || v6.is_unicast_link_local()
                || v6.is_unique_local()
                || ip_in_network(
                    IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0)),
                    32,
                    ip,
                )
                || v6
                    .to_ipv4_mapped()
                    .is_some_and(|v4| ip_is_denied_class(IpAddr::V4(v4)))
        }
    }
}

fn is_metadata_v4(v4: Ipv4Addr) -> bool {
    v4.octets() == [169, 254, 169, 254]
}

fn parse_list(raw: &str) -> Result<Vec<ListEntry>, String> {
    let mut out = Vec::new();
    for item in raw.split(',') {
        let item = item.trim();
        if item.is_empty() {
            continue;
        }
        if let Some((addr, prefix)) = item.split_once('/') {
            let network: IpAddr = addr
                .parse()
                .map_err(|_| format!("invalid CIDR address {addr}"))?;
            let prefix_len: u8 = prefix
                .parse()
                .map_err(|_| format!("invalid CIDR prefix {prefix}"))?;
            out.push(ListEntry::Cidr {
                network,
                prefix_len,
            });
            continue;
        }
        let host = item.trim_start_matches("*").trim_start_matches('.');
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        if item.starts_with("*.") || item.starts_with('.') {
            out.push(ListEntry::Suffix(format!(".{host}")));
        } else {
            out.push(ListEntry::Hostname(host));
        }
    }
    Ok(out)
}

fn matching_host(entry: &ListEntry, host: &str, ips: &[IpAddr]) -> bool {
    match entry {
        ListEntry::Hostname(expected) => host.eq_ignore_ascii_case(expected),
        ListEntry::Suffix(suffix) => host.ends_with(suffix) && host != &suffix[1..],
        ListEntry::Cidr {
            network,
            prefix_len,
        } => ips
            .iter()
            .any(|ip| ip_in_network(*network, *prefix_len, *ip)),
    }
}

impl DestinationPolicy {
    fn matching_entry<'a>(
        &'a self,
        list: &'a [ListEntry],
        host: &str,
        ips: &[IpAddr],
    ) -> Option<&'a ListEntry> {
        list.iter().find(|entry| matching_host(entry, host, ips))
    }
}

fn entry_label(entry: &ListEntry) -> String {
    match entry {
        ListEntry::Hostname(h) => h.clone(),
        ListEntry::Suffix(s) => format!("*{s}"),
        ListEntry::Cidr {
            network,
            prefix_len,
        } => format!("{network}/{prefix_len}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    struct MapResolver(HashMap<String, Vec<IpAddr>>);

    impl HostResolver for MapResolver {
        fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, String> {
            self.0
                .get(host)
                .cloned()
                .ok_or_else(|| format!("no fixture for {host}"))
        }
    }

    fn resolver(pairs: &[(&str, &str)]) -> MapResolver {
        let mut map = HashMap::new();
        for (host, ip) in pairs {
            map.insert(
                (*host).to_string(),
                vec![ip.parse::<IpAddr>().expect("fixture ip")],
            );
        }
        MapResolver(map)
    }

    fn deny(policy: &DestinationPolicy, url: &str, resolver: &MapResolver, needle: &str) {
        let err = policy.evaluate(url, resolver).unwrap_err();
        assert!(
            err.contains(needle),
            "expected {needle:?} in {err:?} for {url}"
        );
        assert!(
            !err.contains('@') && !err.contains("://user"),
            "decision must not leak credentials: {err}"
        );
    }

    #[test]
    fn production_denies_ssrf_classes_and_ambiguous_spellings() {
        let policy = DestinationPolicy::production();
        let dns = resolver(&[
            ("evil.example", "10.0.0.5"),
            ("meta.example", "169.254.169.254"),
            ("mixed.example", "203.0.113.10"),
            ("cgnat.example", "100.64.0.1"),
            ("ula.example", "fd12:3456:789a::1"),
        ]);
        deny(&policy, "http://127.0.0.1/", &dns, "denied address class");
        deny(&policy, "http://0.0.0.0/", &dns, "denied address class");
        deny(
            &policy,
            "http://192.168.1.10/",
            &dns,
            "denied address class",
        );
        deny(
            &policy,
            "http://169.254.169.254/",
            &dns,
            "denied address class",
        );
        deny(&policy, "http://[::1]/", &dns, "denied address class");
        deny(&policy, "http://[fe80::1]/", &dns, "denied address class");
        deny(
            &policy,
            "http://[::ffff:127.0.0.1]/",
            &dns,
            "denied address class",
        );
        deny(&policy, "http://2130706433/", &dns, "denied");
        deny(&policy, "http://0x7f.0.0.1/", &dns, "denied");
        deny(&policy, "http://0177.0.0.1/", &dns, "denied");
        deny(&policy, "https://user:pass@example.com/", &dns, "userinfo");
        deny(&policy, "https://example.com/#frag", &dns, "fragment");
        deny(&policy, "ftp://example.com/", &dns, "not http or https");
        deny(
            &policy,
            "http://evil.example/",
            &dns,
            "denied address class",
        );
        deny(
            &policy,
            "http://meta.example/",
            &dns,
            "denied address class",
        );
        deny(
            &policy,
            "http://cgnat.example/",
            &dns,
            "denied address class",
        );
        deny(&policy, "http://ula.example/", &dns, "denied address class");
        deny(
            &policy,
            "https://example.com:8443/",
            &dns,
            "not a default http/https port",
        );
    }

    #[test]
    fn mixed_public_and_denied_answers_fail_closed() {
        let policy = DestinationPolicy::production();
        let mut map = HashMap::new();
        map.insert(
            "split.example".to_string(),
            vec!["8.8.8.8".parse().unwrap(), "10.1.1.1".parse().unwrap()],
        );
        let dns = MapResolver(map);
        deny(
            &policy,
            "https://split.example/",
            &dns,
            "denied address class 10.1.1.1",
        );
    }

    #[test]
    fn allowlist_permits_otherwise_denied_class_and_denylist_wins() {
        let policy = DestinationPolicy::production()
            .with_lists("10.0.0.0/8,*.internal.example", "blocked.internal.example")
            .unwrap();
        let dns = resolver(&[
            ("svc.internal.example", "10.2.3.4"),
            ("blocked.internal.example", "10.2.3.5"),
            ("public.example", "8.8.8.8"),
        ]);
        policy
            .evaluate("https://svc.internal.example/", &dns)
            .unwrap();
        deny(
            &policy,
            "https://blocked.internal.example/",
            &dns,
            "denied by denylist",
        );
        policy.evaluate("https://public.example/", &dns).unwrap();
    }

    #[test]
    fn development_allows_loopback_but_still_denies_rfc1918() {
        let policy = DestinationPolicy::development();
        let dns = resolver(&[("app.local", "127.0.0.1")]);
        policy
            .evaluate("http://127.0.0.1:80/healthz", &dns)
            .unwrap();
        policy.evaluate("http://localhost/", &dns).unwrap();
        deny(&policy, "http://10.0.0.8/", &dns, "denied address class");
    }

    #[test]
    fn trailing_dot_host_still_matches_allowlist() {
        let policy = DestinationPolicy::production()
            .with_lists("origin.example", "")
            .unwrap();
        let dns = resolver(&[("origin.example", "8.8.4.4")]);
        policy
            .evaluate("https://origin.example./path", &dns)
            .unwrap();
    }
}
