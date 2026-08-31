# Product and technical gap baseline

Snapshot date: 2026-08-31T14:25:00+09:00 (live exact-head GitHub inventory for `ContextualWisdomLab/wardnet`).

## 1. Executive summary

`main` is at commit `b2bcee3bf2c63f26c48e3be879e5349ef23fafcd`. The product direction remains the Rust-first Wardnet gateway described in the current PRD/TRD and ADR set:

- PRD/TRD: [docs/superpowers/specs/2026-07-02-waf-ids-ai-soc-design.md](docs/superpowers/specs/2026-07-02-waf-ids-ai-soc-design.md), [docs/superpowers/specs/2026-07-02-commercial-sale-readiness-design.md](docs/superpowers/specs/2026-07-02-commercial-sale-readiness-design.md), and [docs/superpowers/specs/2026-07-02-program-completion-baseline-design.md](docs/superpowers/specs/2026-07-02-program-completion-baseline-design.md)
- ADR: [docs/adr/0010-adaptive-contextual-orchestrator-default.md](docs/adr/0010-adaptive-contextual-orchestrator-default.md)

Commercial-readiness progress is real, but protected-branch evidence does not yet support a merge-ready claim for the open delivery stack. The current blockers are not hypothetical: they are live GitHub branch-protection requirements, unresolved review findings on the exact current heads, and missing independent approval.

## 2. Protected-branch gate

Organization ruleset `18156473` currently requires:

- 1 independent approving review
- resolved review threads
- required workflows for `Close Empty PR`, `Required OpenCode Review`, `Required PR Review Merge Scheduler`, `Security Scan`, `Strix Security Scan`, `SAST Semgrep`, and `Required Noema Review`

No open PR may be treated as ready until its current head satisfies those exact rules.

## 3. Open PR inventory

There are 17 other open PRs at this exact head, intentionally excluding this
baseline PR (`#130`) from the table below.

| PR | Head | State | Exact-head evidence | Current next action |
| --- | --- | --- | --- | --- |
| [#135](https://github.com/ContextualWisdomLab/wardnet/pull/135) | `a9b88b9801` | Blocked | `opencode-review` and `strix` failed on the current head; 3 unresolved review threads remain; no independent approval | Resolve the current exact-head review findings, then rerun the external review gates and obtain an independent approval |
| [#134](https://github.com/ContextualWisdomLab/wardnet/pull/134) | `d98b9e25d7` | Behind | No unresolved review threads; prior hosted checks on 2026-08-30 were green except the required current-head `opencode-review` verdict; independent review still required | Rebase onto `main`, refresh current-head checks, then obtain an independent approval |
| [#131](https://github.com/ContextualWisdomLab/wardnet/pull/131) | `bcbb90132b` | Dirty | 1 unresolved review thread remains on the current head; merge conflicts with `main`; no independent approval | Rebase onto `main`, clear the remaining exact-head thread, rerun checks, then obtain an independent approval |
| [#129](https://github.com/ContextualWisdomLab/wardnet/pull/129) | `6eea1293bb` | Draft, intentionally blocked | Current exact head is intentionally RED: `noema-review`, `opencode-review`, and `strix` failed; no unresolved threads; independent review still required; must not be merged in this state | Keep the PR in draft, finish the remaining service/docs slices, then replace the intentionally red head with a green exact head before requesting approval |
| [#127](https://github.com/ContextualWisdomLab/wardnet/pull/127) | `69884c95dd` | Blocked | No unresolved review threads; current head is blocked pending required review/gate outcomes; independent approval still required | Revalidate the current hosted gates, then obtain an independent approval |
| [#126](https://github.com/ContextualWisdomLab/wardnet/pull/126) | `5e00a3da49` | Blocked | No unresolved review threads; current head is blocked pending required review/gate outcomes; independent approval still required | Revalidate the current hosted gates, then obtain an independent approval |
| [#115](https://github.com/ContextualWisdomLab/wardnet/pull/115) | `aad8224ab6` | Blocked | `opencode-review` and `strix` failed on the current head; no unresolved threads; independent review still required | Re-run the external review gates on a fresh head, then obtain approval |
| [#114](https://github.com/ContextualWisdomLab/wardnet/pull/114) | `95da92339f` | Blocked | `strix` failed on the current head; no unresolved threads; independent review still required | Wait for a current-head Strix verdict and an independent approval |
| [#112](https://github.com/ContextualWisdomLab/wardnet/pull/112) | `bab3c72bb7` | Blocked | No unresolved threads; some current-head hosted checks completed successfully, but the now-required `Strix Security Scan` result is absent, so the gate is not green; independent review still required | Re-run `Strix Security Scan` on the current head, then obtain an independent approval |
| [#111](https://github.com/ContextualWisdomLab/wardnet/pull/111) | `d65d6cd178` | Blocked | 4 unresolved review threads remain on the current head; no independent approval | Resolve the current exact-head threads, then obtain an independent approval |
| [#95](https://github.com/ContextualWisdomLab/wardnet/pull/95) | `304f053013` | Dirty | `Strix Security Scan` failed; the current head also lacks a passing current-head `opencode-review` verdict; 2 unresolved review threads remain; no independent approval | Clear the current review threads, rerun the current-head review gates, then obtain approval |
| [#94](https://github.com/ContextualWisdomLab/wardnet/pull/94) | `0d2c4952ab` | Blocked | 7 unresolved review threads remain on the current head; no independent approval | Triage and resolve the current exact-head review threads before requesting refreshed gate runs or approval |
| [#93](https://github.com/ContextualWisdomLab/wardnet/pull/93) | `b0f4e1c4f2` | Blocked | No unresolved review threads; current head is blocked pending required review/gate outcomes; independent approval still required | Revalidate the current hosted gates, then obtain an independent approval |
| [#90](https://github.com/ContextualWisdomLab/wardnet/pull/90) | `8b13ba26c1` | Blocked | 2 unresolved review threads remain on the current head; no independent approval | Resolve the current exact-head review threads, then obtain an independent approval after gates are current |
| [#88](https://github.com/ContextualWisdomLab/wardnet/pull/88) | `e693a085b4` | Blocked | No unresolved review threads; current head is blocked pending required review/gate outcomes; independent approval still required | Revalidate the current hosted gates, then obtain an independent approval |
| [#77](https://github.com/ContextualWisdomLab/wardnet/pull/77) | `947394fcdc` | Blocked | 3 unresolved review threads remain on the current head; no independent approval | Resolve the current exact-head review threads, then obtain an independent approval |
| [#72](https://github.com/ContextualWisdomLab/wardnet/pull/72) | `892f9277ba` | Blocked | `strix` failed on the current head; no unresolved threads; independent review still required | Wait for a current-head Strix verdict and an independent approval |

## 4. Open issue inventory

There are 16 open issues. The highest-impact live backlog items are:

- [#128](https://github.com/ContextualWisdomLab/wardnet/issues/128): gate AI-agent package installation against untrusted `llms.txt` and web instructions
- [#87](https://github.com/ContextualWisdomLab/wardnet/issues/87): close the evidence-backed production readiness gate
- [#86](https://github.com/ContextualWisdomLab/wardnet/issues/86): put proven WAF/IDS engines in the enforcement path and publish detection-quality evidence
- [#85](https://github.com/ContextualWisdomLab/wardnet/issues/85): establish production telemetry, SLOs, incident response, and disaster-recovery evidence
- [#84](https://github.com/ContextualWisdomLab/wardnet/issues/84): complete immutable signed release, promotion, and rollback evidence
- [#83](https://github.com/ContextualWisdomLab/wardnet/issues/83): add bounded admission control and trusted client attribution
- [#82](https://github.com/ContextualWisdomLab/wardnet/issues/82): integrate Keyverse identity and tenant authorization evidence

## 5. Product gaps against current requirements

Relative to the current PRD/TRD/ADR set, the main unproven or unmerged requirements are:

- Proven-engine enforcement is still not merged to `main`, so Wardnet cannot yet truthfully claim in-path Coraza-backed enforcement on the protected branch.
- PostgreSQL control-plane authority, tenant-isolated backup and restore, and transactional outbox durability are still in the open PR stack rather than on `main`.
- The Wardnet rename is still incomplete on the protected branch; customer-facing and artifact-facing naming remains mixed until [#114](https://github.com/ContextualWisdomLab/wardnet/pull/114) lands.
- Exact-head hosted evidence is unstable for the highest-value stack: [#135](https://github.com/ContextualWisdomLab/wardnet/pull/135) currently has failing external review checks and unresolved threads on August 31, 2026, [#115](https://github.com/ContextualWisdomLab/wardnet/pull/115) still has failing external review checks, and [#95](https://github.com/ContextualWisdomLab/wardnet/pull/95) remains conflicted with failed required workflows plus unresolved review threads on its current head.
- Commercial-readiness proof remains incomplete for release promotion, telemetry/SLO evidence, accessibility/screenshot evidence, and customer-facing production-readiness packaging.

## 6. Next-step order

1. Land the exact-head review and hosted-check fixes on [#135](https://github.com/ContextualWisdomLab/wardnet/pull/135), [#95](https://github.com/ContextualWisdomLab/wardnet/pull/95), and [#115](https://github.com/ContextualWisdomLab/wardnet/pull/115) without bypassing branch protection.
2. Rebase the behind-but-clean branches such as [#134](https://github.com/ContextualWisdomLab/wardnet/pull/134) and this baseline PR so current-head required workflows can rerun against `main`.
3. Merge blocked-but-clean documentation and rename PRs only after they receive an independent approval on their current heads.
4. Convert the remaining commercial-readiness gaps into reviewable PRs with runnable evidence, prioritizing production-readiness proof over broad scope expansion.
