//! Fail2ban-style client bans for gateway routes.
//!
//! A client that collects `strikes` auth failures inside `window_secs` is
//! banned for `ban_secs`; every later ban doubles, capped at `max_ban_secs`.
//! A banned client is refused before scoring, the WAF engine or the upstream.

use std::{collections::HashMap, net::IpAddr};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BanPolicy {
    /// Strikes that trigger a ban. Zero disables banning.
    pub strikes: u32,
    pub window_secs: u64,
    pub ban_secs: u64,
    pub max_ban_secs: u64,
    /// Upper bound on tracked clients, so a spray of new addresses cannot
    /// grow memory without limit.
    pub max_tracked: usize,
}

impl BanPolicy {
    pub const DISABLED: Self = Self {
        strikes: 0,
        window_secs: 60,
        ban_secs: 600,
        max_ban_secs: 86_400,
        max_tracked: 100_000,
    };
}

#[derive(Debug, Clone, Copy, Default)]
struct Client {
    window_start: u64,
    strikes: u32,
    banned_until: u64,
    /// Bans served so far; drives the escalation.
    offences: u32,
    last_seen: u64,
}

#[derive(Debug)]
pub struct BanTable {
    policy: BanPolicy,
    clients: HashMap<IpAddr, Client>,
}

impl BanTable {
    pub fn new(policy: BanPolicy) -> Self {
        Self {
            policy,
            clients: HashMap::new(),
        }
    }

    /// Seconds left on an active ban, or `None` when the client may proceed.
    pub fn banned_for(&self, ip: IpAddr, now: u64) -> Option<u64> {
        self.clients
            .get(&ip)
            .filter(|client| client.banned_until > now)
            .map(|client| client.banned_until - now)
    }

    /// Records one auth failure. Returns the ban length when this strike bans.
    pub fn strike(&mut self, ip: IpAddr, now: u64) -> Option<u64> {
        if self.policy.strikes == 0 {
            return None;
        }
        if !self.clients.contains_key(&ip) && self.clients.len() >= self.policy.max_tracked {
            self.prune(now);
            if self.clients.len() >= self.policy.max_tracked {
                // ponytail: a full table stops tracking new clients instead of
                // evicting live ones; the credential gate still refuses them.
                return None;
            }
        }
        let policy = self.policy;
        let client = self.clients.entry(ip).or_default();
        client.last_seen = now;
        if client.banned_until > now {
            return None;
        }
        if now.saturating_sub(client.window_start) >= policy.window_secs {
            client.window_start = now;
            client.strikes = 0;
        }
        client.strikes += 1;
        if client.strikes < policy.strikes {
            return None;
        }
        let shift = client.offences.min(32);
        let length = policy
            .ban_secs
            .saturating_mul(1u64 << shift)
            .min(policy.max_ban_secs);
        client.offences = client.offences.saturating_add(1);
        client.strikes = 0;
        client.banned_until = now.saturating_add(length);
        Some(length)
    }

    /// Drops clients that are neither banned nor seen within the longest ban,
    /// which is also how long an offence history is remembered.
    fn prune(&mut self, now: u64) {
        let memory = self.policy.max_ban_secs.max(self.policy.window_secs);
        self.clients.retain(|_, client| {
            client.banned_until > now || now.saturating_sub(client.last_seen) < memory
        });
    }

    #[cfg(test)]
    fn tracked(&self) -> usize {
        self.clients.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const IP: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 7));

    fn policy() -> BanPolicy {
        BanPolicy {
            strikes: 3,
            window_secs: 60,
            ban_secs: 100,
            max_ban_secs: 350,
            max_tracked: 4,
        }
    }

    #[test]
    fn bans_after_strikes_inside_the_window_and_escalates() {
        let mut table = BanTable::new(policy());
        assert_eq!(table.strike(IP, 0), None);
        assert_eq!(table.strike(IP, 1), None);
        assert_eq!(table.strike(IP, 2), Some(100));
        assert_eq!(table.banned_for(IP, 50), Some(52));
        assert_eq!(table.banned_for(IP, 102), None);
        for now in 200..202 {
            assert_eq!(table.strike(IP, now), None);
        }
        assert_eq!(table.strike(IP, 202), Some(200));
        for now in 500..502 {
            table.strike(IP, now);
        }
        assert_eq!(table.strike(IP, 502), Some(350), "capped at max_ban_secs");
    }

    #[test]
    fn strikes_outside_the_window_do_not_accumulate() {
        let mut table = BanTable::new(policy());
        table.strike(IP, 0);
        table.strike(IP, 1);
        assert_eq!(table.strike(IP, 61), None);
        assert_eq!(table.banned_for(IP, 61), None);
    }

    #[test]
    fn strikes_during_a_ban_do_not_extend_it() {
        let mut table = BanTable::new(policy());
        for now in 0..3 {
            table.strike(IP, now);
        }
        assert_eq!(table.strike(IP, 10), None);
        assert_eq!(table.banned_for(IP, 10), Some(92));
    }

    #[test]
    fn disabled_policy_never_bans() {
        let mut table = BanTable::new(BanPolicy::DISABLED);
        for now in 0..100 {
            assert_eq!(table.strike(IP, now), None);
        }
        assert_eq!(table.tracked(), 0);
    }

    #[test]
    fn full_table_prunes_idle_clients_and_refuses_growth_when_all_live() {
        let mut table = BanTable::new(policy());
        for last in 1..=4u8 {
            table.strike(IpAddr::V4(std::net::Ipv4Addr::new(198, 51, 100, last)), 0);
        }
        assert_eq!(table.tracked(), 4);
        assert_eq!(table.strike(IP, 10), None);
        assert_eq!(table.tracked(), 4, "live clients are kept");
        table.strike(IP, 1_000);
        assert_eq!(table.tracked(), 1, "idle clients were pruned");
    }
}
