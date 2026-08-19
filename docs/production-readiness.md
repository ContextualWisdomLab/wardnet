# Wardnet production-readiness audit

> **Verdict: NOT PRODUCTION READY**
>
> Production claims remain prohibited while `docs/production-readiness.json` reports
> `overall_status: blocked` and `production_claim_allowed: false`.

| Field | Value |
| --- | --- |
| Audit date | 2026-08-19 (Asia/Seoul) |
| Audited ref | `refs/heads/main` |
| Audited commit | `b53dc7a1b8904a16752abbdc04429df893a4e32e` |
| Authority issue | #87 |

## Why the gate is blocked

This audit covers the runtime, deployment assets, protected-base CI, threat and
compliance documents, operational runbook, open issues, and active hardening PRs.
The repository is a meaningful Rust gateway/SOC control-plane and controlled-lab
baseline, but its own evidence does not support an internet-facing production claim.

| Evidence | Finding | Consequence |
| --- | --- | --- |
| `README.md` | Not a complete WAF/IDS and not hardened for internet-facing use. | Pilot/readiness endpoints cannot be treated as production certification. |
| `src/lib.rs` | Missing credentials disable management auth; JSON file state; per-process attacker-cardinality-sensitive limiter; scheme-only upstream validation. | Auth, SSRF, HA/state, and overload blockers remain. |
| `docs/security/threat-model.md` | Identity, SSRF, database/backup, DoS, DNS, and secret hardening remain open. | The documented trust boundaries are incomplete. |
| `docs/security/compliance-mapping.md` | Signed release/SBOM, MFA/SCIM, immutable audit, encryption, approval, HA, SLO/on-call, and AI governance remain gaps. | Buyer-lab evidence is not regulated-production evidence. |
| `docs/runbooks/operations.md` | Baseline is limited to local and controlled labs. | Incident, SLO, backup/restore, and game-day operation are unproven. |
| `.github/workflows/ci.yml` | Format, locked tests, and Clippy on a floating compiler channel. | No complete immutable release evidence bundle exists on the audited base. |
| Kubernetes manifest | One replica, file/PVC authority, tag-based image; #72 owns external-secret correction. | HA, immutable promotion, and secret hardening must still land. |

## Mandatory P0 gates

- #72 — external secret boundary, graceful shutdown, and 100% production line/branch coverage.
- #11 — Strix attacks against the real production-shaped deployment.
- #78 — fail closed when a non-loopback listener has no authentication authority.
- #79 — one deny-by-default SSRF/destination policy for every outbound surface.
- #80 — PostgreSQL production authority, tenant ownership/RLS, integrity, migrations, backup, and restore.
- #81 — transactional outbox, durable leases/retries/idempotency, dead letter, and replay.
- #86 — Coraza/OWASP CRS and Suricata in the live path with detection and false-positive evidence.

## Mandatory P1 operating gates

P1 indicates execution order, not optionality for the production designation.

- #74 — deterministic standalone persistence failure tests.
- #75 — hardened Wardnet manifest rename after #72.
- #77 — one pinned Rust toolchain for local and CI builds.
- #82 — Keyverse identity, tenant/resource authorization, lifecycle revocation, consent/approval, separation of duties, and audit context.
- #83 — bounded local protection, trusted client attribution, distributed admission authority, and backpressure.
- #84 — full checks, SBOM, signature, SLSA provenance, deployment by digest, promotion, changelog, and rehearsed rollback.
- #85 — correlated telemetry, SLO/error-budget alerts, incident game day, and measured backup restore.

Issue #38 is a useful quarantine-sandbox/AI SOC expansion, but it cannot substitute
for the mandatory controls above.

## Production definition

Wardnet may leave `blocked` only when one immutable release digest proves:

1. **Security:** no unauthenticated or cross-tenant management path; external secrets;
   uniform destination enforcement; tested deny/degraded-dependency behavior.
2. **Product:** proven WAF/IDS engines evaluate traffic and authenticated sensor evidence;
   AI is advisory until an authorized human approval is committed.
3. **Data:** PostgreSQL constraints and default-deny RLS, compatible migrations, atomic
   audit/outbox, backup/restore, and measured RPO/RTO.
4. **Availability:** multi-replica-safe state/admission/workers; bounded memory, request,
   queue, concurrency, and timeout behavior; graceful shutdown and truthful probes.
5. **Identity/governance:** Keyverse-backed identity, tenant/resource authorization,
   lifecycle revocation, separation of duties, break-glass review, and audit provenance.
6. **Supply chain:** pinned tools/actions/bases/dependencies; meaningful 100% production
   statement/branch coverage; security/fuzz/smoke/attack gates; SBOM, signature,
   provenance, immutable promotion, release notes, and rollback evidence.
7. **Operations:** correlated, redacted telemetry; owned SLOs/alerts/runbooks; incident
   evidence; independently restorable backups and successful game days.
8. **Review:** exact-current-head checks, zero unresolved actionable threads, qualifying
   independent non-author/non-last-pusher approval, and no protected-branch bypass.

## Responsibility boundaries

- **Wardnet:** WAF/IDS and gateway policy, route/resource authorization, destination
  enforcement, allow/monitor/block/step-up/deny decisions, local overload protection,
  and Wardnet audit evidence.
- **Keyverse:** verified subject/tenant/service identity and lifecycle signals; claims do
  not bypass Wardnet authorization.
- **Noema:** shared distributed rate-limit authority if adopted; Wardnet still owns
  local circuit breaking, traffic-class policy, and HTTP behavior.
- **contextual-orchestrator:** model selection and SOC analysis, never enforcement authority.
- **Billing/credit owner:** atomic ledger and cost execution; Wardnet emits idempotent
  risk/usage references and records receipts.
- **Clearfolio/other consumers:** retain their own data authorization and accept only
  authorized, signed, audience-bound evidence.
- **EgressWeave/future integrations:** require an explicit versioned contract; no shared
  database, credential, or authority is assumed.

## Evidence and status transition

Every blocker PR must provide a narrow RED reproduction and GREEN proof, realistic
malformed-input/concurrency/restart/dependency/authorization cases, meaningful 100%
production statement and branch coverage, public API/rustdoc coverage, migration and
rollback notes, operator/incident documentation, source-backed rationale, exact-head
CI/security/attack evidence, and current review/thread state.

To change the status:

1. Verify every mandatory issue is closed by merged implementation, not prose.
2. Bind the audit to one immutable image digest and source SHA.
3. Verify tests, coverage, security, SBOM, signature, provenance, deployment, attack,
   restore, rollback, SLO, and incident-game-day evidence.
4. Re-fetch checks, reviews, and unresolved threads for that exact candidate head.
5. Update this report and the JSON record together in a reviewed PR. Never carry
   evidence forward from a predecessor head.

## References

- National Institute of Standards and Technology. (2022). *Secure software development
  framework (SSDF) version 1.1* (NIST SP 800-218). https://doi.org/10.6028/NIST.SP.800-218
- Nelson, A., Rekhi, S., Souppaya, M., & Scarfone, K. (2025). *Incident response
  recommendations and considerations for cybersecurity risk management: A CSF 2.0
  community profile* (NIST SP 800-61 Rev. 3). https://doi.org/10.6028/NIST.SP.800-61r3
- OWASP Foundation. (2025). *OWASP Application Security Verification Standard 5.0.0*.
  https://owasp.org/www-project-application-security-verification-standard/
- SLSA Project. (2025). *SLSA specification version 1.2*. https://slsa.dev/spec/v1.2/
- Kubernetes Authors. (2026). *Pod Security Standards*.
  https://kubernetes.io/docs/concepts/security/pod-security-standards/
- PostgreSQL Global Development Group. (2026). *PostgreSQL 18 documentation: Row
  security policies*. https://www.postgresql.org/docs/18/ddl-rowsecurity.html
