# Commercial Sale Readiness Design

## Goal

Advance the runnable WAF/IDS/AI SOC baseline into a credible 2B KRW commercial sale readiness baseline.

## Runtime Changes

- Add tenant and license metadata through `/api/commercial/license`.
- Add computed readiness evidence through `/api/commercial/readiness`.
- Add threat feed import and feed status through `/api/threat-feeds/import` and `/api/threat-feeds`.
- Add `/api/support-bundle` for buyer and support review.
- Extend KPIs with threat feed count.
- Preserve legacy JSON state compatibility through serde defaults.

## Non-Goals

- No Figma Code Connect.
- No hand-rolled full WAF engine.
- No claim of complete IDS/SIEM/SOAR replacement.
- No raw license secret storage.

## Verification Contract

- `cargo fmt --check`
- `cargo test --locked`
- `cargo llvm-cov --workspace --all-features --fail-under-lines 100 --show-missing-lines`
- `cargo clippy --locked -- -D warnings`
- `actionlint`
- `scripts/smoke.sh`
- GitHub PR checks and Scorecard after merge
