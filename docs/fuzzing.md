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
| `fuzz_parse_admin_tokens`   | `waf_ids_ai_soc::parse_admin_tokens`        | no panic; no empty token key; no empty principal actor value |
| `fuzz_dnsbl_zone`           | `waf_ids_core::export_dnsbl_zone` / `validate_dnsbl` | no panic; quoted TXT strings decode losslessly, remain injection-safe and contain at most 255 decoded bytes each (RFC 1035 §3.3/§3.3.14); every published A-record response code is an IPv4 loopback literal (127.0.0.0/8); published TTLs are in 1..=2147483647, while invalid persisted TTLs are omitted |

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

DNSBL publication additionally has a package-local independent oracle in
`crates/waf-ids-core/tests/support/dnsbl_zone.rs`. It checks input-derived A/TXT
counts, owner and source order, lossless metadata and shortest valid TTL per
IPv4 owner without calling the production projection or its limit constant.
The stable shared-owner property always generates at least two publishable
records with valid TTLs; metadata may still contain arbitrary or empty text.
the fuzz harness retains its arbitrary-input pass and adds a bounded shared-owner
positive projection. `dnsbl_zone_oracle.rs` pairs legal controls with malformed
TTL, missing-record and identity/metadata negatives. The same oracle checks
ASCII origin labels of 1..=63 bytes and independently computes the encoded
origin length, including label-length and root octets, with room for all four
reversed IPv4 labels. Invalid origins use the existing `dnsbl.invalid` fallback;
ordinary origin spelling and record evidence remain unchanged. TXT publication
also bounds total RDATA to 65,535 decoded payload-plus-length octets; oversized
persisted metadata is omitted from both record and owner-TTL projections. The
independent oracle computes UTF-8 chunk endpoints from input and counts emitted
length octets; stable boundary properties force near-limit metadata with a
short valid shared-owner control. See `doctoring/dnsbl-txt-rdata-limits.md` for
the actual admission/export/RR-serialization boundary and message-size limits.
Oracle negatives
are test-sensitivity checks, not proof that a fuzz campaign ran.

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
