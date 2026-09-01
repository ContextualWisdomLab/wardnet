# Product and technical gap baseline

Snapshot date: 2026-08-31T14:25:00+09:00 (live exact-head GitHub inventory for `ContextualWisdomLab/wardnet`).

> The inventory table in section 3 is the dated snapshot above, not a perpetual live-status claim. Section 1.1 records targeted later evidence without rewriting unrelated PR states from stale observations.

## 1. Executive summary

`main` is at commit `b2bcee3bf2c63f26c48e3be879e5349ef23fafcd`. The product direction remains the Rust-first Wardnet gateway described in the current PRD/TRD and ADR set:

- PRD/TRD: [superpowers/specs/2026-07-02-waf-ids-ai-soc-design.md](superpowers/specs/2026-07-02-waf-ids-ai-soc-design.md), [superpowers/specs/2026-07-02-commercial-sale-readiness-design.md](superpowers/specs/2026-07-02-commercial-sale-readiness-design.md), and [superpowers/specs/2026-07-02-program-completion-baseline-design.md](superpowers/specs/2026-07-02-program-completion-baseline-design.md)
- ADR: [adr/0010-adaptive-contextual-orchestrator-default.md](adr/0010-adaptive-contextual-orchestrator-default.md)

Commercial-readiness progress is real, but protected-branch evidence does not yet support a merge-ready claim for the open delivery stack. The current blockers are not hypothetical: they are live GitHub branch-protection requirements, unresolved review findings on the exact current heads, and missing independent approval.

### 1.1 Targeted DDD and Agent Artifact Admission refresh — 2026-09-01

PR [#129](https://github.com/ContextualWisdomLab/wardnet/pull/129) now treats **Agent Artifact Admission** as a distinct bounded context inside Wardnet's Security Admission subdomain. Its current responsibility-aligned path is `crates/agent-artifact-admission`, rather than a generic `security`, `services`, `utils`, `common`, or `shared` dumping directory. ADR-0012 and the context map define its Ubiquitous Language, ownership and Anti-Corruption Layer boundaries, while `tests/ddd_architecture_contract.rs` rejects outward dependencies from `admission.rs`/`policy.rs` into Axum, Tokio, filesystem/listener/configuration concerns or concrete audit adapters.

The context currently owns structured `InstallIntent`, reviewed `AdmissionPolicy`, deterministic allow/block evaluation, minimized admission audit facts, and the loopback-only delivery boundary. It explicitly does **not** own package execution/sandboxing, package discovery, Sigstore/TUF/SLSA provider schemas, model orchestration, SIEM projection, or organization-wide workflow/credential authority. Those responsibilities cross only through published contracts or future explicit adapters/Anti-Corruption Layers.

The authenticated `/healthz`, `/v1/policy`, and `/v1/admissions` service, audit-before-response semantics, fail-closed audit outage behavior, OpenAPI contract, context-specific threat model, operations runbook, and standards/APA-7 traceability are implemented on the active PR branch. They are **not protected-main truth until #129 merges**. The exact #129 head observed for this targeted refresh is `ee495f4e90037c3255fc7ec2f8278f1147a485a7`; its repository CI/SAST/Security/Fuzz runs were queued at observation time and therefore non-passing.

DDD fitness also exposes two explicit follow-ups rather than cosmetic refactors:

- `audit.rs` currently contains both the audit contract and the single local file adapter. ADR-0012 deliberately permits this while there is only one concrete backend; adding a second persistence backend is the trigger to split the port from adapters. Splitting it now would add structure without an independently evolving responsibility.
- Wardnet's legacy gateway remains concentrated in a very large root `src/lib.rs` with multiple security concerns. File size alone is not proof that a service split is correct, but it is a monolith-growth signal. Before further broad feature expansion, map its stable responsibilities into bounded contexts, add dependency/ownership fitness tests, and move only responsibility-coherent modules. Prefer a modular monolith unless transaction, deployment, reuse, or policy-lifecycle evidence justifies a separate deployable.

This PR (#130) remains the canonical owner for `docs/product-technical-gap-baseline.md`; #129 must not create a competing copy of this document.

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
| [#129](https://github.com/ContextualWisdomLab/wardnet/pull/129) | `6eea1293bb` | Draft, intentionally blocked | Historical 2026-08-31 snapshot: the then-current head was intentionally RED and lacked independent review. See section 1.1 for the newer targeted #129 evidence. | Keep Draft until the unchanged current head is gate-clean and independently approved; do not transfer evidence from this historical head |
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

- Agent Artifact Admission is implemented only on active PR #129. Until its exact head passes the live repository and organization gates and merges, protected `main` does not provide this pre-execution package-install admission control.
- Proven-engine enforcement is still not merged to `main`, so Wardnet cannot yet truthfully claim in-path Coraza-backed enforcement on the protected branch.
- PostgreSQL control-plane authority, tenant-isolated backup and restore, and transactional outbox durability are still in the open PR stack rather than on `main`.
- The Wardnet rename is still incomplete on the protected branch; customer-facing and artifact-facing naming remains mixed until [#114](https://github.com/ContextualWisdomLab/wardnet/pull/114) lands.
- Exact-head hosted evidence is unstable for the highest-value stack: [#135](https://github.com/ContextualWisdomLab/wardnet/pull/135) currently has failing external review checks and unresolved threads on August 31, 2026, [#115](https://github.com/ContextualWisdomLab/wardnet/pull/115) still has failing external review checks, and [#95](https://github.com/ContextualWisdomLab/wardnet/pull/95) remains conflicted with failed required workflows plus unresolved review threads on its current head.
- Commercial-readiness proof remains incomplete for release promotion, telemetry/SLO evidence, accessibility/screenshot evidence, and customer-facing production-readiness packaging.
- The root gateway module remains a DDD fitness risk because multiple stable security responsibilities still accumulate under the legacy root `src` boundary. The next structural step is responsibility mapping and machine-checkable dependency/ownership constraints, not a mechanical folder shuffle or premature microservice split.

## 6. Next-step order

1. Finish Agent Artifact Admission #129 as one coherent Security Admission bounded context, keeping its domain kernel independent of delivery/infrastructure and requiring unchanged exact-head gates plus independent approval before Ready/merge.
2. Land the exact-head review and hosted-check fixes on [#135](https://github.com/ContextualWisdomLab/wardnet/pull/135), [#95](https://github.com/ContextualWisdomLab/wardnet/pull/95), and [#115](https://github.com/ContextualWisdomLab/wardnet/pull/115) without bypassing branch protection.
3. Rebase the behind-but-clean branches such as [#134](https://github.com/ContextualWisdomLab/wardnet/pull/134) and this baseline PR so current-head required workflows can rerun against `main`.
4. Merge blocked-but-clean documentation and rename PRs only after they receive an independent approval on their current heads.
5. Map the legacy gateway's stable responsibilities into bounded contexts and add architecture fitness tests before another large feature expansion; extract modules only when ownership/reuse/transaction/deployment evidence supports the move.
6. Convert the remaining commercial-readiness gaps into reviewable PRs with runnable evidence, prioritizing production-readiness proof over broad scope expansion.
