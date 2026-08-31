//! Property-based invariant test for the `ADMIN_TOKENS` config parser.
//!
//! Mirrors the `fuzz_parse_admin_tokens` cargo-fuzz target (see `../fuzz`) but
//! runs on stable in the normal `cargo test` suite. Parsing arbitrary operator
//! config must never panic and must never emit an empty token key or empty
//! actor value.

use proptest::prelude::*;
use waf_ids_ai_soc::{parse_admin_tokens, parse_credentials_json};

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
    fn credentials_json_preserves_nonblank_values(raw in ".*") {
        if let Ok(credentials) = parse_credentials_json(&raw) {
            for value in credentials.values() {
                prop_assert!(!value.trim().is_empty(), "credential value must never be blank");
            }
        }
    }
}

#[test]
fn present_blank_and_null_credentials_are_rejected() {
    assert!(parse_credentials_json(r#"{"admin_token":"   "}"#).is_err());
    assert!(parse_credentials_json(r#"{"admin_token":null}"#).is_err());
    assert_eq!(
        parse_credentials_json(r#"{"admin_token":7}"#)
            .unwrap()
            .get("admin_token")
            .map(String::as_str),
        Some("7")
    );
}
