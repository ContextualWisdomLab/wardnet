//! Property-based invariant test for the `ADMIN_TOKENS` config parser.
//!
//! Mirrors the `fuzz_parse_admin_tokens` cargo-fuzz target (see `../fuzz`) but
//! runs on stable in the normal `cargo test` suite. Parsing arbitrary operator
//! config must never panic and must never emit an empty token key or empty
//! actor value. The strict startup parser must also reject the ambiguous
//! separator, duplicate-secret, and role classes that public startup treats as
//! invalid configuration.

use proptest::prelude::*;
use waf_ids_ai_soc::{parse_admin_tokens, parse_admin_tokens_strict};

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
    fn parse_admin_tokens_strict_upholds_invariants_when_it_accepts(raw in ".*") {
        if let Ok(tokens) = parse_admin_tokens_strict(&raw) {
            for (token, principal) in &tokens {
                prop_assert!(!token.is_empty(), "strict token key must never be empty");
                prop_assert!(!principal.actor.is_empty(), "strict actor value must never be empty");
            }
        }
    }

    #[test]
    fn parse_admin_tokens_strict_rejects_duplicate_secrets(
        token in "[A-Za-z0-9._~-]{1,32}",
        first_actor in "[A-Za-z0-9._~-]{1,24}",
        second_actor in "[A-Za-z0-9._~-]{1,24}",
    ) {
        let raw = format!("{token}:{first_actor},{token}:{second_actor}");
        let error = parse_admin_tokens_strict(&raw).unwrap_err();
        prop_assert!(error.contains("duplicate token"), "{error}");
    }

    #[test]
    fn parse_admin_tokens_strict_rejects_blank_separator_entries(
        token in "[A-Za-z0-9._~-]{1,32}",
        actor in "[A-Za-z0-9._~-]{1,24}",
        leading in any::<bool>(),
    ) {
        let valid = format!("{token}:{actor}");
        let raw = if leading {
            format!(",{valid}")
        } else {
            format!("{valid},")
        };
        let error = parse_admin_tokens_strict(&raw).unwrap_err();
        prop_assert!(error.contains("blank entry"), "{error}");
    }

    #[test]
    fn parse_admin_tokens_strict_rejects_unknown_roles(
        token in "[A-Za-z0-9._~-]{1,32}",
        actor in "[A-Za-z0-9._~-]{1,24}",
        role in "[A-Z]{5,16}",
    ) {
        prop_assume!(!matches!(role.to_ascii_lowercase().as_str(),
            "admin" | "write" | "writer" | "operator" | "readonly" | "read" | "reader" | "ro"));
        let raw = format!("{token}:{actor}:{role}");
        let error = parse_admin_tokens_strict(&raw).unwrap_err();
        prop_assert!(error.contains("not recognised"), "{error}");
    }

    #[test]
    fn parse_admin_tokens_strict_preserves_write_role_semantics(
        token in "[A-Za-z0-9._~-]{1,32}",
        actor in "[A-Za-z0-9._~-]{1,24}",
        writable in any::<bool>(),
    ) {
        let role = if writable { "operator" } else { "readonly" };
        let raw = format!("{token}:{actor}:{role}");
        let parsed = parse_admin_tokens_strict(&raw).unwrap();
        let principal = parsed.get(&token).expect("generated token must be present");
        prop_assert_eq!(principal.actor.as_str(), actor.as_str());
        prop_assert_eq!(principal.can_write, writable);
    }
}
