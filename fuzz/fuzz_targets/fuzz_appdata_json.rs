#![no_main]
//! Fuzz the persisted-state deserializer.
//!
//! On startup `load_or_seed_state` (src/lib.rs) reads the state file from disk
//! and does `serde_json::from_str::<AppData>(...)`. That file is an untrusted
//! input surface (an attacker or a corrupted volume can supply arbitrary
//! bytes). Deserialization must only ever return `Ok`/`Err`, never panic, and
//! any value that deserializes must round-trip back through serde_json.

use libfuzzer_sys::fuzz_target;
use waf_ids_core::AppData;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };

    if let Ok(parsed) = serde_json::from_str::<AppData>(text) {
        // Anything that parses must re-serialize without panicking and parse
        // back to an equal value (serde round-trip invariant).
        let reserialized = serde_json::to_string(&parsed).expect("AppData must re-serialize");
        let reparsed: AppData =
            serde_json::from_str(&reserialized).expect("re-serialized AppData must parse");
        assert_eq!(parsed, reparsed, "AppData serde round-trip must be stable");
    }
});
