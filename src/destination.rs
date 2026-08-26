//! Fail-closed destination policy for every outbound URL (issue #79).
//!
//! One checker is used for gateway upstreams, threat-intel fetches, Clearfolio,
//! and SOC-LLM calls. Structural URL parse happens first; DNS answers are then
//! classified. Deny-overrides win over allowlists. Loopback-class destinations
//! are allowed only when [`DestinationPolicy::development`] is selected (the
//! process itself is loopback-only).
//!
//! CIDR allowlist matches apply per resolved address (a private CIDR must not
//! exempt a sibling metadata/link-local answer). Non-default ports are allowed
//! when the host or a resolved CIDR is allowlisted. The outbound HTTP client
//! does not re-resolve: it connects only to addresses recorded by a successful
//! evaluation (Host/SNI stay on the original name).

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs},
    sync::{Arc, Mutex},
};
use waf_ids_core::ip_in_network;

/// Cap on remembered (host → evaluated IPs) pins so a hostile name flood
/// cannot grow the table without bound. Eviction is wholesale, not LRU.
const MAX_DESTINATION_PINS: usize = 4096;

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

    /// Operator-visible policy class (`production` or `development`).
    pub fn mode(&self) -> &'static str {
        if self.allow_loopback_class {
            "development"
        } else {
            "production"
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
        let ips = resolve_host_ips(&parsed.host, resolver)?;
        let host_allowlisted = host_allowlisted(&self.allow, &parsed.host);

        if let Some(entry) = self.matching_entry(&self.deny, &parsed.host, &ips) {
            return Err(format!(
                "destination {} denied by denylist ({})",
                parsed.host,
                entry_label(entry)
            ));
        }

        let every_ip_cidr_allowlisted =
            !ips.is_empty() && ips.iter().all(|ip| cidr_allows(&self.allow, *ip));
        let loopback_ok = self.allow_loopback_class
            && (parsed.host == "localhost" || ips.iter().any(|ip| ip.is_loopback()));
        if parsed.port != 80
            && parsed.port != 443
            && !host_allowlisted
            && !every_ip_cidr_allowlisted
            && !loopback_ok
        {
            return Err(format!(
                "destination port {} is not a default http/https port",
                parsed.port
            ));
        }

        for ip in &ips {
            if ip_is_denied_class(*ip) {
                let this_cidr = cidr_allows(&self.allow, *ip);
                if this_cidr || (self.allow_loopback_class && ip.is_loopback()) {
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

/// Process-local map of hostname → addresses that already passed policy.
///
/// The outbound reqwest client uses [`PinnedDns`] so TCP connects to these
/// addresses and never asks the OS resolver a second time (DNS rebinding /
/// TOCTOU close).
#[derive(Default)]
pub(crate) struct DestinationPins {
    inner: Mutex<HashMap<String, Vec<IpAddr>>>,
}

impl DestinationPins {
    pub(crate) fn record(&self, host: &str, ips: &[IpAddr]) {
        let host = normalize_dns_host(host);
        let mut map = self.inner.lock().expect("destination pin lock");
        if map.len() >= MAX_DESTINATION_PINS {
            map.clear();
        }
        map.insert(host, ips.to_vec());
    }

    pub(crate) fn lookup(&self, host: &str) -> Option<Vec<IpAddr>> {
        let host = normalize_dns_host(host);
        self.inner
            .lock()
            .expect("destination pin lock")
            .get(&host)
            .cloned()
    }
}

/// reqwest DNS resolver that returns only pre-authorized addresses.
pub(crate) struct PinnedDns {
    pins: Arc<DestinationPins>,
}

impl PinnedDns {
    pub(crate) fn new(pins: Arc<DestinationPins>) -> Self {
        Self { pins }
    }
}

#[derive(Debug)]
struct UnpinnedHost(String);

impl std::fmt::Display for UnpinnedHost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "destination host {} is not pre-authorized", self.0)
    }
}

impl std::error::Error for UnpinnedHost {}

impl reqwest::dns::Resolve for PinnedDns {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let pins = Arc::clone(&self.pins);
        let host = name.as_str().to_string();
        Box::pin(async move {
            let Some(ips) = pins.lookup(&host) else {
                return Err(Box::new(UnpinnedHost(normalize_dns_host(&host)))
                    as Box<dyn std::error::Error + Send + Sync>);
            };
            let addrs: Vec<SocketAddr> = ips.into_iter().map(|ip| SocketAddr::new(ip, 0)).collect();
            Ok(Box::new(addrs.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

fn normalize_dns_host(host: &str) -> String {
    host.trim_end_matches('.').to_ascii_lowercase()
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

fn resolve_host_ips(host: &str, resolver: &dyn HostResolver) -> Result<Vec<IpAddr>, String> {
    let mut ips = Vec::new();
    if host == "localhost" {
        ips.push(IpAddr::V4(Ipv4Addr::LOCALHOST));
    } else if let Ok(ip) = host.parse::<IpAddr>() {
        ips.push(canonicalize_ip(ip));
    } else {
        ips = resolver
            .resolve(host)
            .map_err(|error| format!("destination DNS failed for {host}: {error}"))?;
        if ips.is_empty() {
            return Err(format!("destination {host} resolved to no addresses"));
        }
        ips = ips.into_iter().map(canonicalize_ip).collect();
    }
    Ok(ips)
}

fn host_allowlisted(entries: &[ListEntry], host: &str) -> bool {
    entries.iter().any(|entry| match entry {
        ListEntry::Hostname(_) | ListEntry::Suffix(_) => matching_host(entry, host, &[]),
        ListEntry::Cidr { .. } => false,
    })
}

fn cidr_allows(entries: &[ListEntry], ip: IpAddr) -> bool {
    entries.iter().any(|entry| match entry {
        ListEntry::Cidr {
            network,
            prefix_len,
        } => ip_in_network(*network, *prefix_len, ip),
        _ => false,
    })
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
        host: normalize_dns_host(host),
        port,
    })
}

fn host_is_ambiguous_literal(host: &str) -> bool {
    if host.chars().all(|c| c.is_ascii_digit()) {
        return true;
    }
    let lowered = host.to_ascii_lowercase();
    // Bare hex IPv4 (0x7f000001), not a hostname that merely contains "0x".
    if lowered.starts_with("0x")
        && !lowered.contains('.')
        && lowered[2..].chars().all(|c| c.is_ascii_hexdigit())
        && lowered.len() > 2
    {
        return true;
    }
    let octets: Vec<&str> = lowered.split('.').collect();
    if octets.len() != 4 || octets.iter().any(|octet| octet.is_empty()) {
        return false;
    }
    let all_numericish = octets.iter().all(|octet| octet_is_numericish(octet));
    let any_non_decimal = octets.iter().any(|octet| octet_is_hex_or_octal(octet));
    all_numericish && any_non_decimal
}

fn octet_is_numericish(octet: &str) -> bool {
    octet.chars().all(|c| c.is_ascii_digit())
        || (octet.starts_with("0x") && octet[2..].chars().all(|c| c.is_ascii_hexdigit()))
}

fn octet_is_hex_or_octal(octet: &str) -> bool {
    (octet.starts_with("0x")
        && octet.len() > 2
        && octet[2..].chars().all(|c| c.is_ascii_hexdigit()))
        || (octet.len() > 1 && octet.starts_with('0') && octet.chars().all(|c| c.is_ascii_digit()))
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
                || ip_in_network(
                    IpAddr::V6(Ipv6Addr::new(0xfec0, 0, 0, 0, 0, 0, 0, 0)),
                    10,
                    ip,
                )
                || v6
                    .to_ipv4()
                    .is_some_and(|v4| ip_is_denied_class(IpAddr::V4(v4)))
                || (v6.segments()[..6] == [0x64, 0xff9b, 0, 0, 0, 0]
                    && ip_is_denied_class(IpAddr::V4(Ipv4Addr::new(
                        v6.octets()[12],
                        v6.octets()[13],
                        v6.octets()[14],
                        v6.octets()[15],
                    ))))
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
            let max_prefix = match network {
                IpAddr::V4(_) => 32,
                IpAddr::V6(_) => 128,
            };
            if prefix_len > max_prefix {
                return Err(format!(
                    "CIDR prefix {prefix_len} exceeds {max_prefix} for {network}"
                ));
            }
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
            ("example.com", "8.8.8.8"),
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
        deny(
            &policy,
            "http://[::127.0.0.1]/",
            &dns,
            "denied address class",
        );
        deny(
            &policy,
            "http://[64:ff9b::127.0.0.1]/",
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
    fn hostname_allowlist_never_exempts_denied_or_mixed_answers() {
        let policy = DestinationPolicy::production()
            .with_lists("*.internal.example", "")
            .unwrap();
        let mut map = HashMap::new();
        map.insert(
            "svc.internal.example".to_string(),
            vec!["8.8.8.8".parse().unwrap(), "10.2.3.4".parse().unwrap()],
        );
        deny(
            &policy,
            "https://svc.internal.example/",
            &MapResolver(map),
            "denied address class 10.2.3.4",
        );
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

    #[test]
    fn hex_substring_in_a_real_hostname_is_not_an_ip_literal() {
        let policy = DestinationPolicy::production();
        let dns = resolver(&[]);
        deny(
            &policy,
            "https://0x0.st/",
            &dns,
            "destination DNS failed for 0x0.st",
        );
        deny(&policy, "http://0x7f000001/", &dns, "denied");
    }

    #[test]
    fn cidr_allowlist_permits_non_default_port_on_matching_literal() {
        let policy = DestinationPolicy::production()
            .with_lists("10.0.0.0/8", "")
            .unwrap();
        let dns = resolver(&[]);
        policy.evaluate("http://10.1.2.3:8080/", &dns).unwrap();
        deny(
            &policy,
            "http://8.8.8.8:8080/",
            &dns,
            "not a default http/https port",
        );
    }

    #[test]
    fn cidr_allowlist_does_not_exempt_sibling_denied_class_answers() {
        let policy = DestinationPolicy::production()
            .with_lists("10.0.0.0/8", "")
            .unwrap();
        let mut map = HashMap::new();
        map.insert(
            "split.internal".to_string(),
            vec![
                "10.1.1.1".parse().unwrap(),
                "169.254.169.254".parse().unwrap(),
            ],
        );
        let dns = MapResolver(map);
        deny(
            &policy,
            "https://split.internal/",
            &dns,
            "denied address class 169.254.169.254",
        );
    }

    #[test]
    fn cidr_non_default_port_requires_every_answer_to_match() {
        let policy = DestinationPolicy::production()
            .with_lists("10.0.0.0/8", "")
            .unwrap();
        let mut map = HashMap::new();
        map.insert(
            "mixed.example".to_string(),
            vec!["10.1.1.1".parse().unwrap(), "8.8.8.8".parse().unwrap()],
        );
        deny(
            &policy,
            "https://mixed.example:8443/",
            &MapResolver(map),
            "not a default http/https port",
        );
    }

    #[test]
    fn invalid_cidr_prefix_is_rejected_at_parse() {
        let v4 = DestinationPolicy::production().with_lists("10.0.0.0/33", "");
        assert!(
            v4.unwrap_err().contains("CIDR prefix 33 exceeds 32"),
            "IPv4 prefix must be at most /32"
        );
        let v6 = DestinationPolicy::production().with_lists("2001:db8::/129", "");
        assert!(
            v6.unwrap_err().contains("CIDR prefix 129 exceeds 128"),
            "IPv6 prefix must be at most /128"
        );
    }

    #[test]
    fn production_denies_deprecated_ipv6_site_local() {
        let policy = DestinationPolicy::production();
        let dns = resolver(&[]);
        deny(&policy, "http://[fec0::1]/", &dns, "denied address class");
        assert_eq!(policy.mode(), "production");
        assert_eq!(DestinationPolicy::development().mode(), "development");
    }

    #[test]
    fn pin_board_records_evaluated_ips_and_normalizes_the_host() {
        let pins = DestinationPins::default();
        let loopback: IpAddr = "127.0.0.1".parse().unwrap();
        pins.record("Pin-Test.invalid.", &[loopback]);
        assert_eq!(pins.lookup("pin-test.invalid"), Some(vec![loopback]));
        assert_eq!(pins.lookup("PIN-TEST.invalid."), Some(vec![loopback]));
        assert!(pins.lookup("other.invalid").is_none());
    }

    #[test]
    fn pin_board_evicts_when_the_cap_is_exceeded() {
        let pins = DestinationPins::default();
        let loopback: IpAddr = "127.0.0.1".parse().unwrap();
        for i in 0..MAX_DESTINATION_PINS {
            pins.record(&format!("host{i}.invalid"), &[loopback]);
        }
        pins.record("overflow.invalid", &[loopback]);
        assert!(
            pins.lookup("host0.invalid").is_none(),
            "wholesale eviction must drop the oldest batch"
        );
        assert_eq!(pins.lookup("overflow.invalid"), Some(vec![loopback]));
    }
}
