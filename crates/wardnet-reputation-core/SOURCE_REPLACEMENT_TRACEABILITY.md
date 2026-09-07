# Atomic Source Replacement Traceability

## Problem

Exact source-generation membership and producer-record lifecycle cursors prevent several replay classes, but they did not provide one bounded operation for publishing a complete authenticated source generation. A caller could manually assemble the next `EvidenceSnapshotV1`, leaving incomplete/truncated refresh rejection and last-known-good replacement discipline outside the Wardnet evidence-admission contract.

A second review finding showed that a replacement could also reuse an existing source's immutable `source_generation` while changing the records or source-completion metadata, provided the outer Wardnet evidence generation changed. That would let different source state share one immutable generation identity.

A third review finding showed that a caller could CAS from the exact prior source generation to a distinct generation token whose authenticated `completed_at_unix` moved backwards. Because source-generation tokens are intentionally opaque, distinct identity alone does not prove forward source progress. Accepting the rollback would allow older source state to be republished under a fresh generation identity.

## Constraints and ownership

Wardnet owns reputation/security-evidence admission, immutable snapshot identity, policy semantics, and the proof that admitted records belong to the represented complete source generation. The pure core does not authenticate or fetch a feed, interpret HTTP status codes, decide whether provider pagination is complete, persist durable cursors/snapshots, authorize outbound transport, or mutate Context Graph/EA truth.

Source adapters remain responsible for authenticated provider semantics, including deciding when a provider response is a complete generation and deriving any source-specific ordering information. The generic core treats generation identifiers as bounded opaque strings. It compares exact identity for CAS and rejects equality when an existing immutable generation would be rewritten; it does not infer lexical, numeric, or chronological order from generation tokens. The authenticated source-completion timestamp is nevertheless part of Wardnet's admitted source snapshot, so an existing source may not move that completion point backwards. Equal completion timestamps remain valid because distinct generations can legitimately complete within the same timestamp resolution.

## Alternatives

1. Leave complete-source replacement to callers assembling `EvidenceSnapshotV1` directly. Rejected because incomplete/truncated publication and stale-writer handling would remain convention rather than one Wardnet admission invariant.
2. Treat an empty record list as evidence that a refresh completed. Rejected because `complete empty` and `incomplete/failed` are different security states; absence alone cannot prove completeness.
3. Compare generation identifiers with lexical or numeric ordering. Rejected because producer generation grammars are source-specific and opaque to the generic core.
4. Mutate the existing snapshot in place. Rejected because a failed candidate could expose partial state and makes last-known-good preservation harder to prove.
5. Allow a distinct generation token to carry an earlier completion timestamp. Rejected because token distinctness is not chronological evidence and would permit stale source state to advance CAS while moving the admitted completion point backwards.
6. Require every new generation to have a strictly later completion timestamp. Rejected because the contract timestamp resolution can legitimately assign equal completion time to distinct generations; only regression is invalid.
7. Accept an explicit completeness assertion from the authenticated adapter boundary, bind replacement to the exact prior source generation, reject completion-time regression, construct a new candidate off to the side, and publish only after full aggregate validation. Selected because it makes the generic invariant deterministic without taking adapter, transport, or persistence ownership.

## Decision and invariants

`SourceReplacementBatchV1` carries the explicit complete/incomplete state, the exact expected prior source generation (or `None` for creation), one completed `SourceSnapshotV1`, and the complete set of generation-bound evidence records. `EvidenceSnapshotV1::replace_source` is a pure transition that returns a new snapshot only after validation succeeds.

- `Incomplete` fails before candidate publication; the caller's prior snapshot is untouched by construction.
- A complete authenticated empty generation is valid and removes only records owned by that source.
- Every replacement record must have the exact batch `source_id` and exact new `source_generation`.
- Existing-source replacement is CAS-bound to the exact represented prior generation; source creation requires an absent prior generation and `None` expectation.
- An existing immutable source generation cannot be republished under the same identity, even when the outer evidence generation changes.
- A distinct replacement generation for an existing source cannot set `completed_at_unix` earlier than the represented prior generation. Equality is allowed; `valid_until_unix` is not required to increase because a source may legitimately shorten its validity horizon.
- The next Wardnet `evidence_generation` must differ from the current immutable snapshot identity.
- Unrelated source snapshots and records are retained.
- Schema, text bounds, source uniqueness, duplicate producer-record identity, evidence validity, completion ordering, provenance and lifecycle invariants remain delegated to the existing aggregate validators rather than being reimplemented here.

## RED → GREEN evidence

Issue #188 records the reviewed Task 2 gap and hostile acceptance.

The initial test-only head `64f60c0dfa0ecc4a21d29ce404618bce971ffe4c` preserved production source from exact parent `#187@b549c4e3f894492ae8d235c79f3447440981e3e8`. Hosted CI run `34159300515`, Rust job `101857575281`, passed checkout/toolchain/formatting and failed in `Test` because the source-replacement contract was absent. That is the causal RED for atomic complete-source replacement.

Implementation `cd05b97ae7b7945ebdf000d382b65b8b46fc4bb1` first exposed deterministic formatting, then `b7aabc026ec1d1c842c8ca4f2e38c622599294f2` reached a Rust ownership error in CI run `34159970161`, job `101859505861`. Minimal ownership-order repair `c96f512d4e89529d64a8964cad07b80ee705091f` produced terminal CI GREEN in run `34160079365`, job `101859819975`.

Fresh source review then found immutable source-generation identity reuse. Test-only head `b53ddde9bcd8524658cacac0efe108577bc9dd87` added the hostile same-generation replacement case while production remained unchanged. Hosted CI run `34160409623`, Rust job `101860879692`, passed checkout/toolchain/formatting and failed in `Test` with Rust `E0599` because `SourceReplacementErrorV1::ReusedSourceGeneration` did not exist. Production repair `555c239827822bdae3d8204ef69d2f681e3d6f31` adds the narrow equality rejection after exact prior-generation CAS.

A later exact-source review found source-completion rollback across distinct generation identities. Test-only head `2904f11a47a149e97c1bb8f77fd7cb61376451f1` changed only `tests/evidence_source_replacement.rs` from the then-current exact source. Hosted CI run `34161720520`, Rust job `101864749405`, acquired Ubuntu 24.04, passed exact checkout, toolchain and `cargo fmt --check`, then failed in `Test` while the production error/invariant was absent. Minimal production repair `7a6f56c5b576aa9948d7cd7c9e27310ef0c15212` adds `SourceCompletionRegression` and rejects only `replacement.completed_at_unix < prior.completed_at_unix` after exact prior-generation CAS and immutable-generation reuse checks. Hosted CI run `34161875680`, Rust job `101865199605`, then passed exact checkout, toolchain, formatting, locked workspace tests and strict Clippy on that exact production head. Fuzz evidence is reacquired separately for every subsequent exact head; predecessor GREEN does not transfer.

The current child also covers successful non-empty replacement plus schema, expected-prior-generation bound, source-snapshot time, duplicate-record, create/replace contradiction, immutable evidence-generation reuse, incomplete batch, mixed identity, stale CAS, complete-empty, immutable source-generation reuse, and completion-time regression cases. Every subsequent source or documentation change requires fresh exact-head CI/Fuzz evidence; predecessor GREEN does not transfer.

## Risks and follow-up

This pure operation does not prove durable transactionality. A production adapter/storage slice must atomically bind authenticated provider pagination/completeness, durable producer lifecycle cursors, the accepted `EvidenceSnapshotV1`, crash recovery, retry/idempotency, and last-known-good publication. A refresh failure or provider not-modified response must not rejuvenate `completed_at_unix`, `valid_until_unix`, or otherwise manufacture evidence freshness.

Source-specific adapters must also preserve producer-authenticated lifecycle and ordinal semantics. EgressWeave remains the owner of reusable URL/address/DNS/peer/redirect/proxy/TLS/resource authorization; no network client belongs in this pure replacement contract.
