# Product and technical gap baseline

Snapshot date: 2026-08-30T20:10:00+09:00 (live exact-head GitHub inventory for `ContextualWisdomLab/wardnet`).

## 1. Executive summary

`main` is at commit `107117634764c901dff540044585d64088fafedb`. The product direction remains the Rust-first Wardnet gateway described in the current PRD/TRD and ADR set:

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

There are 15 other open PRs at this exact head, intentionally excluding this
baseline PR (`#130`) from the table below.

| PR | Head | State | Exact-head evidence | Current next action |
| --- | --- | --- | --- | --- |
| [#131](https://github.com/ContextualWisdomLab/wardnet/pull/131) | `82caad04c0` | Blocked, current-head checks in progress | Fresh head pushed on 2026-08-30; `CI`, `CodeQL`, `Fuzz`, `Security Scan`, `Strix Security Scan`, `Required OpenCode Review`, and `Required Noema Review` are queued or in progress on the new exact head; independent review still required | Wait for the exact-head checks to finish, resolve any current findings, then obtain an independent approval |
| [#129](https://github.com/ContextualWisdomLab/wardnet/pull/129) | `6eea1293bb` | Draft, intentionally blocked | Current exact head is intentionally RED: `noema-review`, `opencode-review`, and `strix` failed; no unresolved threads; independent review still required; must not be merged in this state | Keep the PR in draft, finish the remaining service/docs slices, then replace the intentionally red head with a green exact head before requesting approval |
| [#127](https://github.com/ContextualWisdomLab/wardnet/pull/127) | `aa29565948` | Blocked | `strix` failed on the current head; no unresolved threads; independent review still required | Wait for a current-head Strix verdict and an independent approval |
| [#126](https://github.com/ContextualWisdomLab/wardnet/pull/126) | `41d7ba9e8f` | Blocked | `strix` failed on the current head; no unresolved threads; independent review still required | Wait for a current-head Strix verdict and an independent approval |
| [#115](https://github.com/ContextualWisdomLab/wardnet/pull/115) | `aad8224ab6` | Blocked | `opencode-review` and `strix` failed on the current head; no unresolved threads; independent review still required | Re-run the external review gates on a fresh head, then obtain approval |
| [#114](https://github.com/ContextualWisdomLab/wardnet/pull/114) | `95da92339f` | Blocked | `strix` failed on the current head; no unresolved threads; independent review still required | Wait for a current-head Strix verdict and an independent approval |
| [#112](https://github.com/ContextualWisdomLab/wardnet/pull/112) | `bab3c72bb7` | Blocked | No unresolved threads; some current-head hosted checks completed successfully, but the now-required `Strix Security Scan` result is absent, so the gate is not green; independent review still required | Re-run `Strix Security Scan` on the current head, then obtain an independent approval |
| [#111](https://github.com/ContextualWisdomLab/wardnet/pull/111) | `43369a8801` | Blocked | No unresolved threads; all current hosted checks are green; independent review still required | Obtain an independent approval on the current head |
| [#95](https://github.com/ContextualWisdomLab/wardnet/pull/95) | `304f053013` | Blocked | `required-workflow-bootstrap` failed on the current head; `Strix Security Scan` also failed; `opencode-review` did not produce a current-head verdict; 2 unresolved review threads remain; no independent approval | Clear the current review threads, rerun the current-head review gates, then obtain approval |
| [#94](https://github.com/ContextualWisdomLab/wardnet/pull/94) | `d7fa9a16a7` | Blocked | `strix` failed on the current head; no unresolved threads; independent review still required | Wait for a current-head Strix verdict and an independent approval |
| [#93](https://github.com/ContextualWisdomLab/wardnet/pull/93) | `b38feb9489` | Blocked | `strix` failed on the current head; no unresolved threads; independent review still required | Wait for a current-head Strix verdict and an independent approval |
| [#90](https://github.com/ContextualWisdomLab/wardnet/pull/90) | `e316d4b08e` | Blocked | `strix` failed on the current head; no unresolved threads; independent review still required | Wait for a current-head Strix verdict and an independent approval |
| [#88](https://github.com/ContextualWisdomLab/wardnet/pull/88) | `cbe21a11ab` | Blocked | `strix` failed on the current head; no unresolved threads; independent review still required | Wait for a current-head Strix verdict and an independent approval |
| [#77](https://github.com/ContextualWisdomLab/wardnet/pull/77) | `17cca73671` | Blocked | `strix` failed on the current head; no unresolved threads; independent review still required | Wait for a current-head Strix verdict and an independent approval |
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
- Exact-head hosted evidence is unstable for the highest-value stack: [#115](https://github.com/ContextualWisdomLab/wardnet/pull/115) currently has failing external review checks, and [#95](https://github.com/ContextualWisdomLab/wardnet/pull/95) still has multiple failed required workflows plus unresolved review threads on its current head.
- Commercial-readiness proof remains incomplete for release promotion, telemetry/SLO evidence, accessibility/screenshot evidence, and customer-facing production-readiness packaging.

## 6. Next-step order

1. Land the exact-head review and hosted-check fixes on [#95](https://github.com/ContextualWisdomLab/wardnet/pull/95) and [#115](https://github.com/ContextualWisdomLab/wardnet/pull/115) without bypassing branch protection.
2. Merge blocked-but-clean documentation and rename PRs only after they receive an independent approval on their current heads.
3. Convert the remaining commercial-readiness gaps into reviewable PRs with runnable evidence, prioritizing production-readiness proof over broad scope expansion.
