# Product and technical gap baseline

Snapshot date: 2026-08-23T20:06Z (exact-head inventory of then-open GitHub PRs
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
| [#105](https://github.com/ContextualWisdomLab/wardnet/pull/105) | feat(store): optimistic concurrency on postgres snapshots | `feat/issue-80-optimistic-concurrency` stacked on #99 | Devin still-valid startup-version 409 fixed this pass (`load_postgres` advances `snapshot_version` after save); local fmt/test/clippy + two `/healthz` smokes | Author; Devin COMMENTED (startup false-conflict addressed) | Org 2-approval + self-author. Merge #95 then #96 then #97 then #98 then #99 first. Do not `--admin`. Do not re-implement HASH/role/backup. |
| [#104](https://github.com/ContextualWisdomLab/wardnet/pull/104) | feat(store): HASH-partition security_event by tenant | merged into rustls stack then #99 | prior hour | Author prior hour | Folded into #99. Do not re-implement. |
| [#103](https://github.com/ContextualWisdomLab/wardnet/pull/103) | feat(store): non-owner PostgreSQL runtime role after migrate | `feat/issue-80-runtime-role` stacked on #100 | still-valid Devin restore-window finding fixed this pass (`MIN_RESTORABLE_SCHEMA_VERSION=2`); local fmt/test/clippy + smokes | Author this pass; Devin COMMENTED (v3 backup voiding addressed) | Org 2-approval + self-author. Merge #95 then #96 then #97 then #98 then #99 then #100 first. Do not `--admin`. Do not re-implement rustls, outbox, retention, backup, or HASH. |
| [#102](https://github.com/ContextualWisdomLab/wardnet/pull/102) | feat(store): logical backup and isolated restore drill | squash-merged into #100 (`321e792`) | prior hour | Author prior hour | Folded into rustls stack. Do not re-implement. |
| [#101](https://github.com/ContextualWisdomLab/wardnet/pull/101) | feat(store): bound outbox listing and prune processed rows | `feat/issue-81-outbox-retention` (`0c2167a`) stacked on #100 | still-valid Devin prune-cap finding fixed this pass (`EVENT_LIMIT` on save/ack) | Author; Devin COMMENTED (prune thread addressed) | Org 2-approval + self-author. Merge #95 then #96 then #97 then #98 then #99 then #100 first. Do not `--admin`. |
| [#100](https://github.com/ContextualWisdomLab/wardnet/pull/100) | feat(store): rustls for production PostgreSQL `sslmode=require` | `feat/issue-80-postgres-rustls` stacked on #99 | local fmt/test/clippy + two `/healthz` smokes; live `sslmode=require` fails closed against plaintext postgres | Author this pass | Org 2-approval + self-author. Merge #95 then #96 then #97 then #98 then #99 first. Do not `--admin`. Do not re-implement the postgres gate or outbox. |
| [#99](https://github.com/ContextualWisdomLab/wardnet/pull/99) | feat(store): transactional outbox and leased workers | `feat/issue-81-outbox-workers` stacked on #98 | local fmt/test/clippy + two `/healthz` smokes + postgres `/healthz.outbox=ready` prior hour | Author; Devin COMMENTED (unbounded list closed on #101) | Org 2-approval + self-author. Merge #95 then #96 then #97 then #98 first. Do not `--admin`. |
| [#98](https://github.com/ContextualWisdomLab/wardnet/pull/98) | feat(store): require PostgreSQL as the production control plane | `ea621985e276` (`feat/issue-80-postgres-control-plane`) stacked on #97 | rust + fuzz green at last snapshot; Devin 7 threads (full-snapshot rewrite, ORDER BY, TLS, RLS owner, reconnect) | Author this pass; Devin COMMENTED | Org 2-approval + self-author. ORDER BY + incremental event persist on #99; rustls on #100; backup/restore this pass. Remaining non-owner role. Do not `--admin`. |
| [#97](https://github.com/ContextualWisdomLab/wardnet/pull/97) | feat(waf): evaluate live gateway transactions with in-process libcoraza | `feat/issue-86-in-process-libcoraza` stacked on #96 | local fmt/test/clippy + two `/healthz` smokes prior hour | Author this pass | Org 2-approval + self-author. Merge #95 then #96 first. Do not `--admin`. Do not re-implement sidecar or pin. |
| [#96](https://github.com/ContextualWisdomLab/wardnet/pull/96) | feat(security): fail-closed destination policy for outbound HTTP | `7cacaf135179` (`feat/issue-79-destination-policy`) stacked on #95 | rust + fuzz green at last snapshot; remaining Devin threads are info/KV-deviation | Author this pass; Devin/Codex COMMENTED | Org 2-approval + self-author. Merge #95 first. Do not re-implement the TCP-peer pin. |
| [#95](https://github.com/ContextualWisdomLab/wardnet/pull/95) | feat(waf): consult Coraza sidecar on live gateway transactions | `ba9ee3a0b142` (`feat/issue-86-in-path-coraza`) | rust + Security Scan green at last snapshot | Author this pass; Devin/Codex COMMENTED | Org 2-approval + self-author. Do not re-implement sidecar slice. |
| [#94](https://github.com/ContextualWisdomLab/wardnet/pull/94) | fix(auth): fail closed without write-capable admin on public bind | `f31d960a0b52` (`fix/issue-78-fail-closed-credentials`) | Checks re-ran after readiness-order fix | Author `seonghobae`; Devin COMMENTED | Org 2-approval + self-author. Do not `--admin` merge. Do not re-implement #78. |
| [#93](https://github.com/ContextualWisdomLab/wardnet/pull/93) | test(persistence): replace permission-based fault injection with a deterministic seam | `f77eb69748ec` | rust + Security Scan green; **strix FAILURE** (org LiteLLM provider `openai-direct/gpt-5.6-luna`) | Author `seonghobae`; Devin COMMENTED | strix org-provider FAILURE + 2-approval + self-author. Do not rotate review-agent keys. |
| [#92](https://github.com/ContextualWisdomLab/wardnet/pull/92) | build(deps): bump github/codeql-action/upload-sarif from 4.37.6 to 4.37.7 | dependabot `17277d78d5e1` | All green. `--auto` squash already enabled. | Maintainer APPROVED (1 of 2). | **Second independent APPROVE missing**. `gh pr merge` rejected by ruleset 18156473. |
| [#91](https://github.com/ContextualWisdomLab/wardnet/pull/91) | build(deps): bump futures-util from 0.3.33 to 0.3.34 | dependabot `c4662caebfa1` | All green. `--auto` squash already enabled. | Maintainer APPROVED (1 of 2). | Same as #92: second independent APPROVE missing. |
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
| [#81](https://github.com/ContextualWisdomLab/wardnet/issues/81) | [P0] Add a transactional outbox and idempotent leased workers for external effects | **critical — first slice on #99; retention on #101; TAXII/Clearfolio/orchestrator consumers this pass** |
| [#80](https://github.com/ContextualWisdomLab/wardnet/issues/80) | [P0] Add an authoritative PostgreSQL control plane with tenant isolation and recoverable migrations | **critical — gate on #98; rustls/backup/role/HASH on #99; OCC on #105** |
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

### Proven-engine enforcement (issue #86) — **in-process libcoraza shipped, unmerged**

Coraza/Suricata ingest still maps proven-engine hits into DNSBL + threat
indicators. PR #95 consults a Coraza sidecar on each live `/gateway`
transaction when `CORAZA_WAF_URL` is set. PR #97 `dlopen`s operator-supplied
libcoraza (`CORAZA_LIB_PATH` + `CORAZA_RULES_PATH` and/or `CORAZA_DIRECTIVES`)
and evaluates the same live transactions through the libcoraza C ABI
(`src/coraza_inprocess.rs`). In-process wins over sidecar when both are set.
Missing library, missing rules, or an empty ruleset fail startup before bind.
`GET /api/waf/engine-status` and `/healthz.proven_engine` report
`coraza_in_process` / `coraza_sidecar` / `ingest_hints_only`. Do not re-implement.

### Identity (issue #82, Keyverse)

Management auth is shared secrets (`X-Admin-Token`) plus optional multi-token
RBAC. Keyverse (OIDC/SCIM/FIDO2) is not wired. Fail-closed (#78) is the
prerequisite shipped on PR #94.

### Durable control plane (issue #80) — **production gate on #98; rustls on #100; backup on #102; runtime role on #103; HASH this pass**

PostgreSQL is required for non-loopback binds (`CONTROL_PLANE_DATABASE_URL`).
`src/control_plane.rs` migrates 3NF two-word tables with default-deny RLS
(`FORCE ROW LEVEL SECURITY`, `wardnet.tenant_id`). Snapshot persist is one
transaction. JSON file / memory remain loopback/community only.
`/healthz.persistence` is `postgres` | `file` | `memory`. `sslmode=require`
/ `verify-ca` / `verify-full` use rustls with Mozilla roots (certificates
always verified; stricter than libpq `require`). `allow` / `prefer` are
rejected. `GET /api/backup` exports a hashed logical snapshot; `POST /api/backup`
restores after schema and payload-hash checks; `POST /api/backup/drill` restores
into an isolated tenant, compares unmasked invariants, and drops the drill
tenant. Declared RPO: last successful export. Declared RTO: 60s.
`/healthz.backup` is `ready` on PostgreSQL, `disabled` on file/memory.
Runtime is `wardnet_runtime` (NOSUPERUSER, NOBYPASSRLS) after migrate.
Logical restore accepts schema 2 through the current migration version
(`MIN_RESTORABLE_SCHEMA_VERSION`); role-only and HASH-layout migrations do not
void pre-upgrade snapshots. `security_event` is `PARTITION BY HASH (tenant_id)`
with 8 children. Unpartitioned tables convert in place under `pg_advisory_lock`.
`/healthz.event_partitions` is 8 on PostgreSQL, 0 on file/memory. Client IPs
and paths stay unmasked across convert. Optimistic concurrency is on #105
(`tenant_account.snapshot_version`, HTTP 409; startup save now advances the
in-memory token). Physical/PITR backups stay a DBA concern.

### Transactional outbox (issue #81) — **first slice on #99; retention on #101**

On the PostgreSQL authority, security events append (`security_event` +
`outbox_message`) in one transaction instead of rewriting every table.
Policy snapshots enqueue `policy.snapshot_replaced`. A leased worker claims
with `FOR UPDATE SKIP LOCKED`, retries with bounded exponential backoff,
dead-letters permanent/exhausted failures, and records unique receipts.
Stdout SIEM export is **at-least-once**; the receipt is the exactly-once ack.
Operator-visible: `/healthz.outbox` (`ready`|`disabled`), pending/leased/
dead-letter counts, `GET /api/outbox` (admin read), `POST /api/outbox/{id}/replay`
(admin write + audit). Client IPs and paths in payloads are not masked.
File/memory adapters stay `outbox=disabled` with in-process stdout. `GET /api/outbox`
is bounded to `EVENT_LIMIT`; processed rows prune to that cap on append, snapshot
save, and worker ack; dead letters stay. TAXII poll, Clearfolio submit, and
contextual-orchestrator analysis enqueue on PostgreSQL (`taxii.collection_polled`,
`clearfolio.document_submitted`, `soc.analysis_requested`) and return HTTP 202.
`GET /api/outbox/{id}` returns receipt evidence. Secrets never enter payloads
(`taxii_bearer` / `soc_llm_token` in the credential registry). File/memory stays
synchronous. LLM analysis is advisory and never auto-enforces. Client IPs, paths,
and indicator values stay unmasked.

### Fail-closed credentials (issue #78) — **closed on PR #94**

Shipped on `fix/issue-78-fail-closed-credentials`. Do not re-implement.

### Destination policy (issue #79) — **closed on PR #96 (review-hardening)**

Shipped in `src/destination.rs` including the TCP-peer pin. Do not re-implement
the pin. Remaining: Kubernetes NetworkPolicy examples as defense in depth.
Production sidecar URLs on loopback/private still need `DESTINATION_ALLOWLIST`
(in-process libcoraza does not).

### SIEM / OpenTelemetry (issue #85 / PR #90)

`/api/events.ndjson` and stdout JSON lines exist on main. Full exporter binary
and OTel sit on PR #90, blocked by the 2-approval ruleset. The #81 worker now
replays `security_event.recorded` as stdout SIEM with receipts.

### UI-UX / Storybook / Figma

| Item | Status |
| --- | --- |
| Design tokens | CSS custom properties in `ADMIN_HTML`; documented in `docs/design-system.md` |
| Figma design file | `QTH5UuU0FJv2VyM2xb02Fp` — ADR 0001 |
| FigJam architecture | `JExziD87eUWKLERECUGhWQ` |
| Figma Code Connect | Not used |
| Ten UI-UX areas | Inventoried in `docs/ui-ux/storybook-scene-inventory.md` |
| Node Storybook | **Not hosted in `/admin`** (embedded-console architecture). File:// inventory is the scene/edge-case contract this pass. |
| Outbox card | Embedded `/admin` Outbox section |
| Backup card | Embedded `/admin` Control-plane backup section |
| Event partitions KPI | Embedded `/admin` KPI tile from `/healthz.event_partitions` this pass |

### CSAP / SOC 2 vs PII unmasking

No certification claim. Compliance map lists SSDLC, access control, audit,
availability gaps (signed releases, SSO, HA storage). PII masking would stop
SOC work; we do not ship it. Controls: authn/z, audit, secret hygiene,
future encryption-at-rest.

### Coverage / docstring bar

Org 100% line/branch/docstring applies to **changed** surfaces this loop
(HASH convert SQL, restorable schema window, `/healthz.event_partitions`,
admin KPI tile, probe upgrade preserving unmasked IPs/paths). Remaining
holes on untouched handlers stay listed for later loops.

### Ecosystem connectors (leverage order)

1. **keyverse** — identity for management plane (#82).
2. **contextual-orchestrator** — SOC LLM optional via `SOC_LLM_BASE_URL`;
   token from credential registry (`soc_llm_token`). Same outbox contract on
   PostgreSQL this pass. Do not fork routing.
3. **naruon** / **clearfolio** — document viewer already optional.
4. **TEPP / RankWeave / ThreadWeave / LineageWeave / disksage / fast-mlsirm** —
   not on the gateway data path; no connector this pass.

## This loop’s shipped gap

Issue **#81** extra consumers stacked on #105: TAXII poll, Clearfolio submit,
and contextual-orchestrator SOC analysis go through the leased outbox on
PostgreSQL. `load_postgres` also advances `snapshot_version` after the startup
save so the first management write cannot false-conflict (Devin #105). Do not
re-implement #78, sidecar, pin, libcoraza, the postgres gate, outbox, rustls,
retention, backup/restore, runtime role, HASH, or OCC.

## Next hourly loop (do, do not report)

1. Second independent APPROVE on #91/#92. Do not `--admin`.
2. Keep #94 independently; #95 then #96 then #97 then #98 then #99 then #105
   then this consumers PR merge-ready. Do not `--admin`.
3. Next runtime gap if policy still blocks: signed release/promotion (#84) or
   Keyverse identity (#82) after the postgres stack.
4. Refresh this file’s PR/Issue tables from `gh pr list` / `gh issue list`.
