# Producer Version Lifecycle Traceability

## Problem

A generation-bound evidence snapshot can prove that a record belongs to the exact completed source generation and can reject a record whose own revoked/deleted state contradicts enforcement eligibility. Those stateless checks do not remember the latest producer-record lifecycle state across generations. Without retained lifecycle state, an older active producer version can be replayed after a later tombstone and appear eligible again.

## Constraints and ownership

Wardnet owns security evidence admission and reputation-policy semantics. It does not fetch feeds, interpret executable destination transport, authorize egress, persist another service's domain truth, or own quarantine execution. Source adapters authenticate producer responses and normalize source-specific ordering semantics. The generic core treats `producer_record_version` as opaque and does not infer ordering lexically or numerically.

The lifecycle cursor is deterministic admission state only. It does not claim durable cursor persistence, transactionality, pagination completeness, authentication of the cursor itself, or source-specific ordinal derivation. The later atomic source-replacement child adds a pure complete-generation snapshot transition, documented in `SOURCE_REPLACEMENT_TRACEABILITY.md`; that transition likewise does not turn this in-memory lifecycle cursor into durable authenticated storage state.

## Alternatives

1. Compare opaque producer version strings lexically. Rejected because producer version grammars are source-specific and lexical order can contradict producer chronology.
2. Parse every producer version as an integer. Rejected because the generic Wardnet contract cannot assume a numeric source grammar.
3. Treat a later active record as implicit withdrawal reversal. Rejected because it permits silent resurrection after a producer tombstone and erases the security significance of explicit withdrawal.
4. Retain an adapter-normalized monotonic ordinal alongside the opaque version token and make a tombstone terminal for the exact producer record identity. Selected because ordering remains source-owned while the pure Wardnet core can fail closed on stale replay, ordinal/token collision, identity substitution, and resurrection.

## Decision and invariants

`ProducerRecordLifecycleCursorV1` binds one exact `(source_id, producer_record_id)` to the latest admitted opaque version token, adapter-normalized monotonic ordinal, and terminal tombstone state.

- A lower ordinal is stale and rejected.
- The same ordinal with a different opaque version token is rejected as an ordering collision.
- A tombstoned identity cannot become active at the same or a later ordinal.
- Replaying the same tombstone/version is idempotent.
- An active identity may advance to a newer active version or transition to a tombstone.
- Source or producer-record identity substitution fails closed.
- Candidate evidence must first satisfy the existing v1 evidence contract, including lifecycle/enforcement eligibility.

A producer that legitimately reintroduces withdrawn evidence must issue a new producer record identity unless a source-specific lifecycle contract is separately reviewed and represented at the adapter boundary.

## Exact evidence

Issue #186 records the reviewed gap and hostile acceptance. Test-only head `76655da309351d50555af475f5dc38e9895680bc` preserved production source from parent #185, passed hosted exact checkout/toolchain/formatting in CI run `34158323025` / Rust job `101854686599`, and then failed at the `Test` step because the required lifecycle cursor/error contract did not yet exist. That is the causal RED for this slice.

The production candidate must obtain fresh unchanged-head formatting, locked workspace tests, strict Clippy, and fuzz evidence. Predecessor results do not transfer.

## Follow-up

The pure atomic source-replacement child now distinguishes complete empty state from incomplete replacement, rejects partial publication, exact-CAS binds an existing source generation, and preserves unrelated last-known-good records. Remaining storage/adapter work must bind both the lifecycle cursor and accepted snapshot to authenticated durable source state in one crash-safe transaction, prove provider pagination/completeness, preserve source-specific ordering semantics, and avoid extending evidence freshness after refresh failure or a provider not-modified outcome. These controls remain behind the canonical source-adapter and storage boundaries rather than being simulated in the pure crate.
