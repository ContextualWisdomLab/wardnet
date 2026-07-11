#![no_main]
//! Fuzz the admin-token config parser: `waf_ids_ai_soc::parse_admin_tokens`.
//!
//! This parses the `ADMIN_TOKENS` operator config string ("token:actor,...")
//! into an RBAC map. Malformed or adversarial config must never panic, and the
//! parser's structural invariants must hold for every input:
//!   * no empty token key ever ends up in the map;
//!   * every actor value is non-empty (defaults to "admin").

use libfuzzer_sys::fuzz_target;
use waf_ids_ai_soc::parse_admin_tokens;

fuzz_target!(|data: &[u8]| {
    let Ok(raw) = std::str::from_utf8(data) else {
        return;
    };

    let tokens = parse_admin_tokens(raw);
    for (token, actor) in &tokens {
        assert!(!token.is_empty(), "token key must never be empty");
        assert!(!actor.is_empty(), "actor value must never be empty");
    }
});
