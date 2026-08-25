# ADR 0005: Coverage-guided fuzzing of untrusted-input surfaces

- Status: Accepted
- Date: 2026-08-25
- Recorded from: current `main` (`docs/fuzzing.md`; README verification
  note; in-repo preprint PDF
  `docs/papers/fuzzing-art-science-engineering-survey-arxiv-1812.00140.pdf`)

## Context

The gateway parses attacker-controlled path, query, body, and client
IP on every request. Startup also deserializes untrusted JSON state
and admin-token configuration. DNSBL zone generation emits text from
operator-supplied reasons and codes.

Manès et al. (2021) survey fuzzing as repeated execution with
generated, often malformed inputs, and treat coverage-guided fuzzing
as a primary engineering method for finding crashes and invariant
violations on those surfaces. This ADR cites that **published** IEEE
Transactions on Software Engineering article as primary. The 2018
arXiv posting is the **preprint** of the same work (Manes et al.,
2018/2019) and is already vendored in-repo. No other fuzzing paper is
cited.

## Decision

1. Exercise the untrusted-input surfaces with **coverage-guided
   fuzzing** (cargo-fuzz / libFuzzer) on nightly:
   - `fuzz_score_request` — `waf_ids_core::score_request`
   - `fuzz_appdata_json` — `AppData` state-file JSON
   - `fuzz_parse_admin_tokens` — admin-token configuration parser
   - `fuzz_dnsbl_zone` — DNSBL zone export / validation
2. Keep a **stable property-test mirror** (`proptest`) in
   `crates/waf-ids-core/tests/fuzz_invariants.rs` and
   `tests/fuzz_invariants.rs` so the same invariants run on stable in
   `cargo test --workspace`.
3. Isolate fuzz targets in the `fuzz/` Cargo workspace so root
   `cargo test --workspace` never builds libFuzzer targets.
4. When an untrusted-input surface changes, keep the libFuzzer target
   and the property-test mirror in sync (`docs/fuzzing.md`).

## Consequences

- Invariants include: no panic on arbitrary input; non-empty score
  reasons; deterministic scoring; serde round-trip of parsed state;
  no empty token key or empty actor; TXT payloads fully escaped;
  every published A-record code in `127.0.0.0/8`.
- Pull-request CI smoke-fuzzes each target for a bounded budget;
  nightly runs a longer budget. Those workflows are operational, not
  additional papers.
- Coverage-gate stubs and cancelled scanner runs are not evidence for
  this decision.

## References

Manès, V. J. M., Han, H., Han, C., Cha, S. K., Egele, M., Schwartz,
E. J., & Woo, M. (2021). The art, science, and engineering of
fuzzing: A survey. *IEEE Transactions on Software Engineering,
47*(11), 2312–2331. https://doi.org/10.1109/TSE.2019.2946563

*(Primary published version. Crossref record confirmed 2026-08-25:
title, volume 47 issue 11, pages 2312–2331, date 2021-11-01. DOI
resolver reached `https://ieeexplore.ieee.org/document/8863940/`.)*

Manes, V. J. M., Han, H., Han, C., Cha, S. K., Egele, M., Schwartz,
E. J., & Woo, M. (2018). The art, science, and engineering of
fuzzing: A survey. *arXiv*.
https://doi.org/10.48550/arXiv.1812.00140

*(Preprint; arXiv:1812.00140. Submitted 2018-12-01, revised 2019-04-08
as v4. Local copy:
`docs/papers/fuzzing-art-science-engineering-survey-arxiv-1812.00140.pdf`.)*
