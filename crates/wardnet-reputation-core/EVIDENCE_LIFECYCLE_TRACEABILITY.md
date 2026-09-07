# Evidence lifecycle enforcement traceability

## Problem and bounded-context ownership

`EvidenceRecordV1` preserves producer lifecycle state (`revoked`, `deleted`) separately from Wardnet's reviewed `enforcement_eligible` flag. Before this repair, those fields were individually representable but not mutually constrained. An otherwise valid record could therefore remain `enforcement_eligible=true` after the producer had marked it revoked or deleted, and a generation-bound `EvidenceSnapshotV1` would accept that contradictory state when its source-generation, time, provenance, and shape checks were otherwise valid.

This is a Wardnet evidence/admission-policy invariant. It does not fetch or refresh source data, define producer deletion semantics, resolve destinations, authorize DNS/peer/redirect/proxy/TLS/resource use, or execute transport. Source acquisition remains outside this pure core, and executable outbound transport authorization remains EgressWeave-owned.

## Decision

A revoked or deleted record cannot remain enforcement eligible. `EvidenceRecordV1::validate_at` fails closed with `LifecycleIneligibleEnforcementEvidence` when `enforcement_eligible` is true and either lifecycle flag is true.

The check intentionally follows the existing schema, bounded-text/list, provenance, time-order, and confidence checks. That preserves deterministic error precedence for malformed evidence instead of allowing lifecycle state to mask an earlier structural or provenance defect.

Producer lifecycle history is not erased. A revoked or deleted record remains a valid historical evidence object when `enforcement_eligible=false`, subject to every other v1 validation rule. This preserves audit/provenance state while preventing historical producer evidence from being serialized as current Wardnet enforcement evidence.

This slice does not claim cross-generation monotonicity. `producer_record_version` is still preserved as producer-native identity, but v1 does not yet maintain prior-generation state that can prove a later generation never replays an older producer version or loses a tombstone. That is a separate source-admission state transition and remains the next Task 2 lifecycle boundary rather than being guessed inside this stateless record validator.

## Alternatives considered

**Ignore producer lifecycle when `enforcement_eligible` is true — rejected.** It creates a contradictory security state in which Wardnet can continue enforcing from evidence that its own contract records as revoked or deleted.

**Reject every revoked or deleted record — rejected.** Revocation/deletion is material historical evidence. Removing those records from the contract would weaken auditability and provenance and would conflate "cannot currently enforce" with "must not be retained as history."

**Silently rewrite `enforcement_eligible=false` during validation — rejected.** Validation must not mutate evidence or manufacture a policy decision. The producer/admission path must present a coherent immutable record; invalid combinations fail closed.

**Treat this record-level check as proof of monotonic tombstone handling across refreshes — rejected.** A stateless record validator cannot establish ordering between producer versions from different completed source generations. That requires explicit admitted-state/version transition semantics and hostile old-version replay coverage.

## Executable evidence

Test-only RED `f5d8f28d32cabca23a90acf86e578faeac703791` was based exactly on `#183@1b183e784750d56d4cbeda469d2ced75811ae08c` and changed only `tests/evidence_lifecycle_enforcement.rs`. The hostile generation-bound fixtures set revoked, deleted, and revoked-plus-deleted evidence to `enforcement_eligible=true`, while controls keep active eligible evidence valid and retain lifecycle-marked history with `enforcement_eligible=false`.

Hosted CI run `34154105805`, Rust job `101842225780`, acquired a GitHub-hosted runner, completed exact checkout, toolchain setup, and formatting, then failed at the `Test` step against unchanged production. That is the causal lifecycle RED.

The minimum production repair adds one invariant and one typed v1 validation error. The subsequent exact-error regression requires every hostile lifecycle combination to return `LifecycleIneligibleEnforcementEvidence`; the positive controls remain unchanged. Exact-current GREEN belongs to the pull request's current immutable head/run receipts and must not be inferred from the RED or any predecessor head.

## Standards relationship

The repository's main `TRACEABILITY.md` remains the normative standards bibliography for this crate. Its NIST CSF 2.0, NIST SP 800-53 Rev. 5, NIST SP 800-218 SSDF 1.1, and CWE-20 mappings support explicit policy/evidence separation, auditability, and strict validation. None of those sources defines Wardnet's `revoked`, `deleted`, `enforcement_eligible`, or `LifecycleIneligibleEnforcementEvidence` fields. The lifecycle rule above is a local bounded-context decision that makes the already-preserved producer lifecycle state mechanically consistent with Wardnet enforcement eligibility.
