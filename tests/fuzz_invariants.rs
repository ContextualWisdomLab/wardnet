//! Property-based invariant test for the `ADMIN_TOKENS` config parser.
//!
//! Mirrors the `fuzz_parse_admin_tokens` cargo-fuzz target (see `../fuzz`) but
//! runs on stable in the normal `cargo test` suite. Parsing arbitrary operator
//! config must never panic and must never emit an empty token key or empty
//! actor value.

use proptest::prelude::*;
use waf_ids_ai_soc::parse_admin_tokens;

proptest! {
    #[test]
    fn parse_admin_tokens_upholds_invariants(raw in ".*") {
        let tokens = parse_admin_tokens(&raw);
        for (token, actor) in &tokens {
            prop_assert!(!token.is_empty(), "token key must never be empty");
            prop_assert!(!actor.is_empty(), "actor value must never be empty");
        }
    }
}
