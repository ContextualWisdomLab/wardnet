#![no_main]
//! Fuzz both admin-token config parsers:
//! `waf_ids_ai_soc::parse_admin_tokens` and
//! `waf_ids_ai_soc::parse_admin_tokens_strict`.
//!
//! Both parse the untrusted `ADMIN_TOKENS` operator config string
//! (`token:actor[:role],...`) into an RBAC principal map. Malformed or
//! adversarial config must never panic. Whenever either parser accepts an
//! input, its structural invariants must hold:
//!   * no empty token key ever ends up in the map;
//!   * every actor value is non-empty (defaults to "admin").
//!
//! The strict startup parser may reject duplicate tokens, blank token entries,
//! or unknown roles; those errors are expected fuzz outcomes rather than
//! crashes.

use libfuzzer_sys::fuzz_target;
use waf_ids_ai_soc::{parse_admin_tokens, parse_admin_tokens_strict, parse_credentials_json};

fuzz_target!(|data: &[u8]| {
    let Ok(raw) = std::str::from_utf8(data) else {
        return;
    };

    let tokens = parse_admin_tokens(raw);
    for (token, principal) in &tokens {
        assert!(!token.is_empty(), "token key must never be empty");
        assert!(
            !principal.actor.is_empty(),
            "actor value must never be empty"
        );
    }

    if let Ok(tokens) = parse_admin_tokens_strict(raw) {
        for (token, principal) in &tokens {
            assert!(!token.is_empty(), "strict token key must never be empty");
            assert!(
                !principal.actor.is_empty(),
                "strict actor value must never be empty"
            );
        }
    }

    if let Ok(credentials) = parse_credentials_json(raw) {
        for value in credentials.values() {
            assert!(!value.trim().is_empty(), "credential value must never be blank");
        }
    }
});
