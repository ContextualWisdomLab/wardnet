# Product and technical gap baseline

Snapshot date: 2026-08-23 (exact-head inventory of then-open GitHub PRs and
Issues plus operator-perceptible gaps). Update this file on every hourly loop.

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
| [#94](https://github.com/ContextualWisdomLab/wardnet/pull/94) | fix(auth): fail closed without write-capable admin on public bind | `fix/issue-78-fail-closed-credentials` | local fmt/test/clippy + two smokes green; GitHub Checks pending at open | Author this pass. | Org 2-approval ruleset + self-author (same as other self-authored PRs). Runtime gap #78 is in this PR. |
| [#93](https://github.com/ContextualWisdomLab/wardnet/pull/93) | test(persistence): replace permission-based fault injection with a deterministic seam | `fix/issue-74-deterministic-persistence-fault` | rust + Security Scan green; **strix FAILURE** (job `97189711094`). Run log HTTP 404 from this token against wardnet and org `.github`. | Author `seonghobae`; Devin comments (info). | (1) strix FAILURE — log not readable (404); (2) org 2-approval ruleset + self-author. |
| [#92](https://github.com/ContextualWisdomLab/wardnet/pull/92) | build(deps): bump github/codeql-action/upload-sarif from 4.37.6 to 4.37.7 | dependabot | All green (27). | Maintainer APPROVED (1 of 2). | Org ruleset: 2 approving reviews. Last pusher is dependabot so this approval counts; **second independent APPROVE missing**. |
| [#91](https://github.com/ContextualWisdomLab/wardnet/pull/91) | build(deps): bump futures-util from 0.3.33 to 0.3.34 | dependabot | All green (27). | Maintainer APPROVED (1 of 2). | Same as #92: second independent APPROVE missing. |
| [#90](https://github.com/ContextualWisdomLab/wardnet/pull/90) | feat(observability): export Wardnet events to SIEM and OpenTelemetry | `feat/siem-opentelemetry-export` | All green (35). | Author `seonghobae`; CodeRabbit/Devin/GHAS comments (redaction of `key: value` credential shapes; `python` vs `python3` in runbook). | Org 2-approval + self-author; unresolved review threads (`required_review_thread_resolution`). |
| [#88](https://github.com/ContextualWisdomLab/wardnet/pull/88) | feat(security): reject non-LiteLLM credentials before upstream | `feat/litellm-virtual-key-ingress-guard` | All green (35). | Author `seonghobae`; CodeRabbit (header length cap, fuzz target, literature). | Org 2-approval + self-author; unresolved threads. |
| [#77](https://github.com/ContextualWisdomLab/wardnet/pull/77) | build(rust): pin and track Rust 1.97.1 | `agent/rust-toolchain-refresh-2026-08-19` | rust green; **strix FAILURE** (job `97001450437`, log 404). | Author `seonghobae`. | strix FAILURE (unread log) + org 2-approval + self-author. |
| [#76](https://github.com/ContextualWisdomLab/wardnet/pull/76) | feat(ai): delegate SOC analysis to adaptive orchestration | `agent/adaptive-orchestrator-default` | All green (35). | Author `seonghobae`; CodeRabbit; opencode DISMISSED. | Org 2-approval + self-author. |
| [#72](https://github.com/ContextualWisdomLab/wardnet/pull/72) | fix(deploy): require externally provisioned admin secret | `automation/remove-placeholder-admin-secret` | All green (35). | Author `seonghobae`; **opencode-agent CHANGES_REQUESTED** (latest); some CodeRabbit threads confirmed fixed but unresolved in GitHub. | `CHANGES_REQUESTED` (opencode-agent) + unresolved threads + org 2-approval + self-author. |

Dependabot #91 and #92 were approved by this actor; `gh pr merge` was rejected
by the base-branch policy (not by failing Checks). Do not `--admin` merge.

## Then-open issues

| Issue | Title | Priority |
| --- | --- | --- |
| [#89](https://github.com/ContextualWisdomLab/wardnet/issues/89) | Fail closed on invalid LiteLLM Virtual Keys and preserve safe upstream auth headers | medium |
| [#87](https://github.com/ContextualWisdomLab/wardnet/issues/87) | [Production readiness] Close the evidence-backed Wardnet production gate | medium |
| [#86](https://github.com/ContextualWisdomLab/wardnet/issues/86) | [P0] Put proven WAF/IDS engines in the enforcement path and publish detection-quality evidence | **critical** |
| [#85](https://github.com/ContextualWisdomLab/wardnet/issues/85) | [P1] Establish production telemetry, SLOs, incident response, and disaster-recovery evidence | high |
| [#84](https://github.com/ContextualWisdomLab/wardnet/issues/84) | [P1] Build an immutable signed release, promotion, and rollback pipeline | high |
| [#83](https://github.com/ContextualWisdomLab/wardnet/issues/83) | [P1] Add bounded distributed admission control, trusted client attribution, and overload behavior | high |
| [#82](https://github.com/ContextualWisdomLab/wardnet/issues/82) | [P1] Integrate Keyverse identity, tenant authorization, consent, and human approval evidence | high (blocked) |
| [#81](https://github.com/ContextualWisdomLab/wardnet/issues/81) | [P0] Add a transactional outbox and idempotent leased workers for external effects | **critical** |
| [#80](https://github.com/ContextualWisdomLab/wardnet/issues/80) | [P0] Add an authoritative PostgreSQL control plane with tenant isolation and recoverable migrations | **critical** |
| [#79](https://github.com/ContextualWisdomLab/wardnet/issues/79) | [P0] Enforce a fail-closed destination policy for all outbound traffic | **critical** |
| [#78](https://github.com/ContextualWisdomLab/wardnet/issues/78) | [P0] Fail closed when management credentials are absent | **critical — closed in runtime this pass** |
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

### Proven-engine enforcement (issue #86) — **partial this pass**

Coraza/Suricata ingest still maps proven-engine hits into DNSBL + threat
indicators. This pass also writes an `engine_payload` hint from the audit URI
query so the **same CRS payload is blocked for any client IP** on `/gateway`
(not only the original source). In-process OWASP CRS/Coraza on every
transaction, Suricata tail/shipper, and detection-quality corpora remain open.

### Identity (issue #82, Keyverse)

Management auth is shared secrets (`X-Admin-Token`) plus optional multi-token
RBAC. Keyverse (OIDC/SCIM/FIDO2) is not wired. Fail-closed (#78) is the
prerequisite shipped this pass.

### Durable control plane (issue #80)

Optional JSON file + atomic rename. Not PostgreSQL, no tenant isolation, no
migrations, no hot-partition strategy. 3NF/snake_case two-word names apply when
the store lands.

### Fail-closed credentials (issue #78) — **closed this pass**

Shipped:

- `require_write_auth_for_bind` in `src/credentials.rs` (driven by unit tests
  and by `run_from_env` / the real binary).
- Non-loopback `BIND_ADDR` without a write-capable principal exits before bind
  (`tests/binary.rs::binary_fail_closes_non_loopback_listen_without_admin`).
- Loopback remains usable; `/healthz.auth_mode` is `development` or `production`.
- `401` vs `403` on management writes; constant-time compare; strict
  `ADMIN_TOKENS` parser.

Doctoring: `docs/doctoring/fail-closed-management-auth.md` (APA 7th).

### Destination policy (issue #79) — **closed this pass**

Shipped in `src/destination.rs` and wired through route upsert, gateway proxy,
threat-intel fetch, Clearfolio, and SOC LLM. Default deny of loopback, RFC 1918,
link-local, ULA, CGNAT, documentation, and cloud-metadata classes unless
`DESTINATION_ALLOWLIST` (or loopback development) permits them.
`DESTINATION_DENYLIST` wins. HTTP clients: no redirects, `no_proxy()`.

Remaining: custom connector that pins the TCP peer to the evaluated IP (full
TOCTOU close); Kubernetes NetworkPolicy examples as defense in depth.

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
(credentials gate, health `auth_mode`, 401/403 helper, binary fail-closed).
Remaining holes on untouched handlers stay listed for later loops.

### Ecosystem connectors (leverage order)

1. **keyverse** — identity for management plane (#82).
2. **contextual-orchestrator** — SOC LLM already optional via
   `SOC_LLM_BASE_URL`; keep adapter, do not fork routing.
3. **naruon** / **clearfolio** — document viewer already optional.
4. **TEPP / RankWeave / ThreadWeave / LineageWeave / disksage / fast-mlsirm** —
   not on the gateway data path; no connector this pass.

## This loop’s shipped gap

Issue **#78**: fail-closed management credentials on non-loopback listen.
Operator-visible: a cluster bind (`0.0.0.0:8080`) without `ADMIN_TOKEN` no
longer becomes ready with open management writes.

## Next hourly loop (do, do not report)

1. Second independent APPROVE on #91/#92 (or OpenCode review agent APPROVE
   without rotating review-agent secrets).
2. Fetch strix logs with an Actions-capable token; fix #93/#77 or re-run.
3. Address remaining CodeRabbit threads on #90/#88 if still on exact head.
4. Destination allowlist (#79) or in-path Coraza evidence (#86) — pick the
   closer mergeable runtime gap.
5. Refresh this file’s PR/Issue tables from `gh pr list` / `gh issue list`.
