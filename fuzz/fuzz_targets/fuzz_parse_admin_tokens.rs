#![no_main]
//! Fuzz the admin-token config parser: `waf_ids_ai_soc::parse_admin_tokens`
//! and the strict startup mirror.
//!
//! This parses the `ADMIN_TOKENS` operator config string
//! (`token:actor[:role],...`) into an RBAC principal map. Malformed or
//! adversarial config must never panic, and the parser's structural invariants
//! must hold for every input:
//!   * no empty token key ever ends up in the map;
//!   * every actor value is non-empty (defaults to "admin");
//!   * the strict startup parser either rejects ambiguous input or yields the
//!     same non-empty token/actor invariants;
//!   * strict startup always rejects duplicate secrets, blank list entries, and
//!     unknown roles, matching the stable proptest mirror.

use libfuzzer_sys::fuzz_target;
use std::fmt::Write as _;
use waf_ids_ai_soc::{parse_admin_tokens, parse_admin_tokens_strict};

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

    // Use fuzz bytes to vary a header-safe token while deterministically driving
    // the strict parser's security-relevant rejection branches. These mirrors
    // remain intentionally simple so a parser change cannot silently make the
    // startup grammar more permissive than its stable property tests.
    let mut seed = String::from("fuzz");
    for byte in data.iter().take(8) {
        write!(&mut seed, "{byte:02x}").expect("writing to String cannot fail");
    }

    let duplicate = format!("{seed}:alice,{seed}:bob");
    assert!(
        parse_admin_tokens_strict(&duplicate).is_err(),
        "strict startup must reject duplicate secrets"
    );

    let blank_entry = format!("{seed}:alice,,other:bob");
    assert!(
        parse_admin_tokens_strict(&blank_entry).is_err(),
        "strict startup must reject blank list entries"
    );

    let unknown_role = format!("{seed}:alice:not-a-role");
    assert!(
        parse_admin_tokens_strict(&unknown_role).is_err(),
        "strict startup must reject unknown roles"
    );
});
