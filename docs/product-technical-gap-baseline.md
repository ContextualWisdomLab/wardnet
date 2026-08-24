# Product and technical gap baseline

Snapshot date: 2026-08-23T16:01Z (exact-head inventory of then-open GitHub PRs
and Issues plus operator-perceptible gaps). Update this file on every hourly loop.

Commercial contract and `/api/commercial/readiness` remain **2B KRW**. The
**$20 billion USD** figure is the long-loop quality bar for this program, not a
number to rewrite into the readiness API this pass.

PII policy: **do not mask** client IPs, paths, indicator values, or actor names
on SOC surfaces. Masking blinds incident response. Alternative controls: fail-closed
authentication, RBAC, audit log, credential registry (no secrets in health/support
bundle), encryption-at-rest when PostgreSQL lands, purpose limitation in runbooks.
CSAP/SOC 2 remain uncertified; see `docs/security/compliance-mapping.md`.

## Then-open pull requests

Org ruleset `CWL Central required workflows` (id `18156473`) requires
**two** approving reviews, `require_last_push_approval=true`, and
`required_review_thread_resolution=true`. Code-owner review is disabled
(solo maintainer). This actor (`seonghobae`) cannot satisfy a second
independent human approval on self-authored PRs and cannot bypass the
ruleset (`current_user_can_bypass: never`). That is a **policy blocker**,
not “waiting on review/CI time”.

| PR | Title | Head | Checks | Reviews | Merge blocker |
| --- | --- | --- | --- | --- | --- |
| [#97](https://github.com/ContextualWisdomLab/wardnet/pull/97) | feat(waf): evaluate live gateway transactions with in-process libcoraza | `feat/issue-86-in-process-libcoraza` stacked on #96 | local fmt/test/clippy + two `/healthz` smokes this hour | Author this pass | Org 2-approval + self-author. Merge #95 then #96 first. Do not `--admin`. Do not re-implement sidecar or pin. |
| [#96](https://github.com/ContextualWisdomLab/wardnet/pull/96) | feat(security): fail-closed destination policy for outbound HTTP | `7cacaf135179` (`feat/issue-79-destination-policy`) stacked on #95 | rust + fuzz green at last snapshot; remaining Devin threads are info/KV-deviation | Author this pass; Devin/Codex COMMENTED. Remaining unresolved: DESTINATION_* env (documented operational-config deviation), hostname-allowlist mixed answers (intended), sidecar loopback needs allowlist in production, pin-cap eviction info | Org 2-approval + self-author. Merge #95 first. Do not re-implement the TCP-peer pin. |
| [#95](https://github.com/ContextualWisdomLab/wardnet/pull/95) | feat(waf): consult Coraza sidecar on live gateway transactions | `ba9ee3a0b142` (`feat/issue-86-in-path-coraza`) | rust + Security Scan green at last snapshot | Author this pass; Devin/Codex COMMENTED | Org 2-approval + self-author. Do not re-implement sidecar slice. |
| [#94](https://github.com/ContextualWisdomLab/wardnet/pull/94) | fix(auth): fail closed without write-capable admin on public bind | `f31d960a0b52` (`fix/issue-78-fail-closed-credentials`) | Checks re-ran after readiness-order fix | Author `seonghobae`; Devin COMMENTED | Org 2-approval + self-author. Do not `--admin` merge. Do not re-implement #78. |
| [#93](https://github.com/ContextualWisdomLab/wardnet/pull/93) | test(persistence): replace permission-based fault injection with a deterministic seam | `f77eb69748ec` | rust + Security Scan green; **strix FAILURE** (org LiteLLM provider `openai-direct/gpt-5.6-luna`) | Author `seonghobae`; Devin COMMENTED | strix org-provider FAILURE + 2-approval + self-author. Do not rotate review-agent keys. |
| [#92](https://github.com/ContextualWisdomLab/wardnet/pull/92) | build(deps): bump github/codeql-action/upload-sarif from 4.37.6 to 4.37.7 | dependabot `17277d78d5e1` | All green. `--auto` squash already enabled. Copilot review re-requested this hour. | Maintainer APPROVED (1 of 2). | **Second independent APPROVE missing**. `gh pr merge` rejected by ruleset 18156473. |
| [#91](https://github.com/ContextualWisdomLab/wardnet/pull/91) | build(deps): bump futures-util from 0.3.33 to 0.3.34 | dependabot `c4662caebfa1` | All green. `--auto` squash already enabled. Copilot review re-requested this hour. | Maintainer APPROVED (1 of 2). | Same as #92: second independent APPROVE missing. |
| [#90](https://github.com/ContextualWisdomLab/wardnet/pull/90) | feat(observability): export Wardnet events to SIEM and OpenTelemetry | `40f11b93a972` | All green (35). | Author `seonghobae`; CodeRabbit/Devin/GHAS COMMENTED. **0 unresolved threads** on exact head. | Org 2-approval + self-author. |
| [#88](https://github.com/ContextualWisdomLab/wardnet/pull/88) | feat(security): reject non-LiteLLM credentials before upstream | `41b21cfe2168` | All green (35). | Author `seonghobae`; CodeRabbit COMMENTED. **0 unresolved threads** on exact head. | Org 2-approval + self-author. |
| [#77](https://github.com/ContextualWisdomLab/wardnet/pull/77) | build(rust): pin and track Rust 1.97.1 | `a13c08656177` | rust green; **strix FAILURE**. Same org-provider fail-closed as #93. | Author `seonghobae`; Devin COMMENTED. | strix org-provider FAILURE + 2-approval + self-author. |
| [#76](https://github.com/ContextualWisdomLab/wardnet/pull/76) | feat(ai): delegate SOC analysis to adaptive orchestration | `1cc492775d26` | All green (35). | Author `seonghobae`; CodeRabbit COMMENTED; opencode DISMISSED. **0 unresolved threads**. | Org 2-approval + self-author. |
| [#72](https://github.com/ContextualWisdomLab/wardnet/pull/72) | fix(deploy): require externally provisioned admin secret | `6881f4799188` | rust/coverage-evidence/opencode-review **success**; **strix FAILURE** (org provider). **0 unresolved threads**. | Latest opencode-agent **CHANGES_REQUESTED** was on `5fd9e2ba`, not this head. | Sticky `CHANGES_REQUESTED` + 2-approval + self-author + strix org-provider FAILURE. |

Dependabot #91 and #92 remain auto-merge enabled; `gh pr merge` was rejected
by ruleset `18156473` (not by failing Checks). Do not `--admin` merge.

## Then-open issues

| Issue | Title | Priority |
| --- | --- | --- |
| [#89](https://github.com/ContextualWisdomLab/wardnet/issues/89) | Fail closed on invalid LiteLLM Virtual Keys and preserve safe upstream auth headers | medium |
| [#87](https://github.com/ContextualWisdomLab/wardnet/issues/87) | [Production readiness] Close the evidence-backed Wardnet production gate | medium |
| [#86](https://github.com/ContextualWisdomLab/wardnet/issues/86) | [P0] Put proven WAF/IDS engines in the enforcement path and publish detection-quality evidence | **critical — in-process + sidecar slices shipped, unmerged** |
| [#85](https://github.com/ContextualWisdomLab/wardnet/issues/85) | [P1] Establish production telemetry, SLOs, incident response, and disaster-recovery evidence | high |
| [#84](https://github.com/ContextualWisdomLab/wardnet/issues/84) | [P1] Build an immutable signed release, promotion, and rollback pipeline | high |
| [#83](https://github.com/ContextualWisdomLab/wardnet/issues/83) | [P1] Add bounded distributed admission control, trusted client attribution, and overload behavior | high |
| [#82](https://github.com/ContextualWisdomLab/wardnet/issues/82) | [P1] Integrate Keyverse identity, tenant authorization, consent, and human approval evidence | high (blocked) |
| [#81](https://github.com/ContextualWisdomLab/wardnet/issues/81) | [P0] Add a transactional outbox and idempotent leased workers for external effects | **critical** |
| [#80](https://github.com/ContextualWisdomLab/wardnet/issues/80) | [P0] Add an authoritative PostgreSQL control plane with tenant isolation and recoverable migrations | **critical** |
| [#79](https://github.com/ContextualWisdomLab/wardnet/issues/79) | [P0] Enforce a fail-closed destination policy for all outbound traffic | **critical — closed in runtime on #96** |
| [#78](https://github.com/ContextualWisdomLab/wardnet/issues/78) | [P0] Fail closed when management credentials are absent | **critical — closed in runtime on #94** |
| [#75](https://github.com/ContextualWisdomLab/wardnet/issues/75) | Rename Kubernetes manifest to wardnet.yaml after external-secret hardening lands | medium |
| [#74](https://github.com/ContextualWisdomLab/wardnet/issues/74) | Make persistence failure tests deterministic across root and constrained filesystems | medium (PR #93) |
| [#38](https://github.com/ContextualWisdomLab/wardnet/issues/38) | AI SOC: quarantine-sandbox malware analysis for attachment/link lures | medium (blocked) |
| [#11](https://github.com/ContextualWisdomLab/wardnet/issues/11) | 서버를 켜고 Strix가 포트를 향해 각종 공격을 할 때 감지해내야 함 (CI) | medium |

## Operator-perceptible product / technical gaps

### Crate / repo name split

GitHub repo and product name are **wardnet**. Cargo package and process log
still say `waf-ids-ai-soc`. Kubernetes manifest remains
`deploy/kubernetes/waf-ids-ai-soc.yaml` (issue #75 waits on #72). Cheap alias
this pass: docs and health copy already mention Wardnet in newer surfaces;
wholesale crate rename is deferred (not a merge blocker).

### Proven-engine enforcement (issue #86) — **in-process libcoraza this pass**

Coraza/Suricata ingest still maps proven-engine hits into DNSBL + threat
indicators. PR #95 consults a Coraza sidecar on each live `/gateway`
transaction when `CORAZA_WAF_URL` is set. This pass also `dlopen`s
operator-supplied libcoraza (`CORAZA_LIB_PATH` + `CORAZA_RULES_PATH` and/or
`CORAZA_DIRECTIVES`) and evaluates the same live transactions through the
libcoraza C ABI (`src/coraza_inprocess.rs`). In-process wins over sidecar when
both are set. Missing library, missing rules, or an empty ruleset fail
startup before bind. `GET /api/waf/engine-status` and `/healthz.proven_engine`
report `coraza_in_process` / `coraza_sidecar` / `ingest_hints_only`. CI stays
hermetic with a fixture cdylib that exports the same symbols; production
points at a real libcoraza + CRS bundle. Suricata tail/shipper and
detection-quality corpora remain open.

### Identity (issue #82, Keyverse)

Management auth is shared secrets (`X-Admin-Token`) plus optional multi-token
RBAC. Keyverse (OIDC/SCIM/FIDO2) is not wired. Fail-closed (#78) is the
prerequisite shipped on PR #94.

### Durable control plane (issue #80)

Optional JSON file + atomic rename. Not PostgreSQL, no tenant isolation, no
migrations, no hot-partition strategy. 3NF/snake_case two-word names apply when
the store lands.

### Fail-closed credentials (issue #78) — **closed on PR #94**

Shipped on `fix/issue-78-fail-closed-credentials`. Do not re-implement.

### Destination policy (issue #79) — **closed on PR #96 (review-hardening)**

Shipped in `src/destination.rs` including the TCP-peer pin. Do not re-implement
the pin. Remaining: Kubernetes NetworkPolicy examples as defense in depth.
Production sidecar URLs on loopback/private still need `DESTINATION_ALLOWLIST`
(in-process libcoraza does not).

### SIEM / OpenTelemetry (issue #85 / PR #90)

`/api/events.ndjson` and stdout JSON lines exist on main. Full exporter binary
and OTel sit on PR #90, blocked by the 2-approval ruleset.

### UI-UX / Storybook / Figma

| Item | Status |
| --- | --- |
| Design tokens | CSS custom properties in `ADMIN_HTML`; documented in `docs/design-system.md` |
| Figma design file | `QTH5UuU0FJv2VyM2xb02Fp` — ADR 0001 |
| FigJam architecture | `JExziD87eUWKLERECUGhWQ` |
| Figma Code Connect | Not used |
| Ten UI-UX areas | Inventoried in `docs/ui-ux/storybook-scene-inventory.md` |
| Node Storybook | **Not hosted in `/admin`** (embedded-console architecture). File:// inventory is the scene/edge-case contract this pass. |

### CSAP / SOC 2 vs PII unmasking

No certification claim. Compliance map lists SSDLC, access control, audit,
availability gaps (signed releases, SSO, HA storage). PII masking would stop
SOC work; we do not ship it. Controls: authn/z, audit, secret hygiene,
future encryption-at-rest.

### Coverage / docstring bar

Org 100% line/branch/docstring applies to **changed** surfaces this loop
(libcoraza loader, engine-status in-process fields, startup fail-closed,
gateway consult). Remaining holes on untouched handlers stay listed for later
loops.

### Ecosystem connectors (leverage order)

1. **keyverse** — identity for management plane (#82).
2. **contextual-orchestrator** — SOC LLM already optional via
   `SOC_LLM_BASE_URL`; keep adapter, do not fork routing.
3. **naruon** / **clearfolio** — document viewer already optional.
4. **TEPP / RankWeave / ThreadWeave / LineageWeave / disksage / fast-mlsirm** —
   not on the gateway data path; no connector this pass.

## This loop’s shipped gap

Issue **#86** slice review-hardening (PR #95): forwarded-header allowlist to
the engine (`host`/`user-agent`/`accept`/`content-type`/`referer`/`origin`/
`x-requested-with`/`x-forwarded-for`/`x-real-ip`/`cookie`; never
`Authorization`; 32 headers / 8 KiB caps), 1 MiB streamed response cap,
explicit status contract (2xx parse, 403 interruption fallback, everything
else `Unavailable`), `engine_hit` evidence on monitor-mode routes and
sub-threshold hits, and `engine_unavailable` events for fail-open outages.
Redirects were already disabled on the shared outbound client. Redistributable
NIST SP 800-94 PDF committed to `docs/papers/` and cited in doctoring.

Issue **#86** slice: in-path Coraza sidecar adapter on live `/gateway`
transactions (branch `feat/issue-86-in-path-coraza`, not stacked onto PR #94
after that PR was restored to issue-#78-only scope). Operator-visible:
`GET /api/waf/engine-status` reports whether CRS is in the request path; a
sidecar interrupt blocks the **current** request (not only a later client
matching ingest hints). #78 remains on PR #94; #79 destination policy was
unscoped from #94 and was not re-implemented here.

Issue **#86** in-process libcoraza remainder ([#97](https://github.com/ContextualWisdomLab/wardnet/pull/97), stacked on #96).
Operator-visible: `CORAZA_LIB_PATH` + `CORAZA_RULES_PATH`/`CORAZA_DIRECTIVES`;
`/healthz.proven_engine=coraza_in_process`; `GET /api/waf/engine-status`
`in_process_configured` / `in_process_rules`; missing library fails before
readiness (`tests/binary.rs::binary_fail_closes_when_libcoraza_path_is_missing`).
Driving tests: `gateway_blocks_live_request_from_in_process_libcoraza` and
`stub_engine_blocks_crs_probe_and_allows_clean`. In-process transactions now
receive the same bounded forwarded-header allowlist as the sidecar (never
`Authorization`). Do not re-implement #78, the #86 sidecar slice, or the #79 pin.

## Next hourly loop (do, do not report)

1. Second independent APPROVE on #91/#92 (Copilot re-requested; still 1/2;
   `--auto` already enabled). Merge if exact-HEAD second independent APPROVE
   exists. Do not `--admin`.
2. Keep #94/#95/#96/#97 merge-ready. Merge order #95 then #96 then #97. Do
   not re-implement #78, the #86 sidecar, or the #79 pin.
3. Strix FAILURE on #72/#77/#93 is org LiteLLM provider infra, not wardnet
   code; do not rotate keys. Watch ContextualWisdomLab/.github branch
   `codex/strix-fail-closed-provider-evidence`.
4. Sticky opencode `CHANGES_REQUESTED` on #72 head `6881f47` — review job does
   not post APPROVE.
5. Next runtime gap if policy still blocks: #80 durable PostgreSQL control
   plane, or #81 outbox/workers, or #86 detection-quality corpora / Suricata
   tail.
6. Refresh this file’s PR/Issue tables from `gh pr list` / `gh issue list`.
