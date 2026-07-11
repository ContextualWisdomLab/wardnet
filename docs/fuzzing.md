# Fuzzing

The gateway parses attacker-controlled bytes on every request and untrusted
state/config on startup, so the highest-value surfaces are exercised with
**coverage-guided fuzzing** (cargo-fuzz / libFuzzer) plus a fast
**property-test** mirror that runs in the normal test suite.

## Target selection

Targets were chosen by mapping the untrusted-input surfaces with CodeGraph
(`codegraph explore "score_request anomaly_signal normalize decode ..."` and
`"parse_admin_tokens load_or_seed_state validate_dnsbl deserialize ..."`), which
surfaced the request scorer, the persisted-state deserializer, the admin-token
config parser, and the DNSBL zone generator as the reachable, no-covering-test
entry points for arbitrary input.

| Fuzz target                 | Surface (function)                          | Invariants |
| --------------------------- | ------------------------------------------- | ---------- |
| `fuzz_score_request`        | `waf_ids_core::score_request`               | no panic on arbitrary path/query/body/IP; `reason` never empty; scoring deterministic |
| `fuzz_appdata_json`         | `serde_json::from_str::<AppData>` (state file) | no panic; parsed values round-trip through serde |
| `fuzz_parse_admin_tokens`   | `waf_ids_ai_soc::parse_admin_tokens`        | no panic; no empty token key; no empty actor value |
| `fuzz_dnsbl_zone`           | `waf_ids_core::export_dnsbl_zone` / `validate_dnsbl` | no panic; every TXT payload fully escaped (no zone break-out) |

## Layout

```
fuzz/                       # separate cargo workspace (isolated from the root
  Cargo.toml                # workspace so `cargo test` at the root is unaffected)
  fuzz_targets/*.rs         # one libFuzzer target per surface
  corpus/<target>/*         # committed seed corpus (attack payloads, edge cases)
```

The property-test mirror lives in `crates/waf-ids-core/tests/fuzz_invariants.rs`
and `tests/fuzz_invariants.rs` (proptest); it enforces the same invariants on
stable as part of `cargo test --workspace`.

## Running locally

Coverage-guided fuzzing needs a nightly toolchain:

```sh
rustup toolchain install nightly
cargo install cargo-fuzz
cargo +nightly fuzz run fuzz_score_request -- -max_total_time=60
```

The stable property-test mirror needs no extra setup:

```sh
cargo test --workspace
```

## CI

`.github/workflows/fuzz.yml` runs each target for a bounded budget:

- **Pull requests:** 60s per target (smoke fuzzing; keeps CI cost predictable).
- **Nightly cron / manual dispatch:** 300s per target (deeper exploration).

Crash-reproducing inputs are uploaded as build artifacts on failure. All fuzzing
dependencies are permissive (cargo-fuzz, libfuzzer-sys, arbitrary, proptest are
each MIT OR Apache-2.0).

## Further reading

- V.J.M. Manès et al., *The Art, Science, and Engineering of Fuzzing: A Survey*
  — [`papers/fuzzing-art-science-engineering-survey-arxiv-1812.00140.pdf`](papers/fuzzing-art-science-engineering-survey-arxiv-1812.00140.pdf).
