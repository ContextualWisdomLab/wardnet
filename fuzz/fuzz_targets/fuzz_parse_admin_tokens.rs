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
//!     unknown roles, matching the stable proptest mirror;
//!   * accepted write/readonly aliases preserve their authorization semantics.

use libfuzzer_sys::fuzz_target;
use std::fmt::Write as _;
use waf_ids_ai_soc::{parse_admin_tokens, parse_admin_tokens_strict};

fuzz_target!(|data: &[u8]| {
    // Derive a header-safe token from arbitrary bytes before UTF-8 decoding so
    // every libFuzzer execution reaches the deterministic security invariants.
    // The arbitrary parser path below remains limited to valid UTF-8 because
    // ADMIN_TOKENS is a string-valued configuration contract.
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

    let writer = format!("{seed}:alice:operator");
    let writer_tokens =
        parse_admin_tokens_strict(&writer).expect("operator role must remain accepted");
    assert!(
        writer_tokens
            .get(&seed)
            .is_some_and(|principal| principal.can_write),
        "operator role must remain write-capable"
    );

    let reader = format!("{seed}:alice:readonly");
    let reader_tokens =
        parse_admin_tokens_strict(&reader).expect("readonly role must remain accepted");
    assert!(
        reader_tokens
            .get(&seed)
            .is_some_and(|principal| !principal.can_write),
        "readonly role must remain non-writing"
    );

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
});
