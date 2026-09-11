# Threat-feed DNSBL snapshot ownership

## Decision boundary

`POST /api/threat-feeds/import` is a snapshot-reconciliation boundary, not an append-only DNSBL ingest path. A feed refresh may withdraw a previously published address. Wardnet therefore distinguishes four facts that the global `Vec<DnsblEntry>` cannot express by itself:

1. the stable DNSBL identity currently used by `upsert_dnsbl`;
2. which feed snapshots still claim that identity;
3. whether an operator independently owns that identity; and
4. the current effective payload stored for that identity.

The stable identity is the same identity the mutation primitive already enforces: IP `address`. Introducing a different ownership key would make reconciliation disagree with `upsert_dnsbl` and would permit two logical owners to mutate one physical row under incompatible identities.

## Implemented state model

The durable `AppData` authority now carries explicit DNSBL ownership rather than inferring it from source strings, TTL, threat indicators, audit logs, or adapter-specific conventions.

- `DnsblEntryKey(IpAddr)` is serializable/hashable and matches the global DNSBL upsert identity.
- Each `ThreatFeedOwnership` carries `dnsbl_keys` with `#[serde(default)]`, so persisted predecessor state loads without a destructive rewrite.
- `AppData` carries independent `operator_dnsbl_keys`, also with `#[serde(default)]`.
- `/api/dnsbl` upsert and operator-key registration occur in the same `mutate_and_persist` mutation, so either the effective payload plus ownership persist together or the mutation rolls back.
- A feed import replaces that feed's threat and DNSBL ownership sets as one snapshot mutation, then removes each previously owned DNSBL row only when no other feed and no operator owns the address.
- Feed import skips effective-payload writes for operator-owned addresses and increments `upserted_dnsbl` only for writes it actually performs.

Ownership metadata is internal control-plane state. It does not become threat intelligence, does not become a synthetic `ThreatIndicator`, and is not encoded into `source`, audit-log text, or another bounded context. Those shortcuts were rejected because they would make authority implicit and break DDD naming and semantic boundaries.

## Replay, persistence, and idempotency

A repeated identical feed snapshot leaves ownership and effective DNSBL state semantically unchanged apart from the feed freshness timestamp already owned by the import path. Restarting from persisted `AppData` retains enough ownership to make the next refresh deterministic; an in-memory sidecar is not sufficient. A refresh of feed A cannot delete an address still owned by feed B. A later operator upsert at an address previously owned by a feed survives withdrawal of that feed without payload rollback.

The repair remains inside Wardnet's shared threat-feed admission/control-plane path. MISP, STIX/TAXII, OpenCTI, KEV, and other adapters provide feed material but do not copy or reimplement reconciliation. This is why the valid review finding was repaired at `apply_threat_feed_import`, not inside `misp_import.rs`.

## Hostile RED and causal GREEN

`tests/threat_feed_dnsbl_ownership.rs` is the focused public-API regression. The corrected hostile lineage reached exact RED `28d0ac12d37b4c97ea58b2d55831a6c1e7b9cf98`: the existing implementation failed stale feed withdrawal and operator-overwrite isolation while the valid shared-feed control remained preserved. The refresh requests retain unrelated valid material so they reach snapshot reconciliation without changing the existing contract that rejects a completely empty feed import.

The hostile contract requires:

- import feed A with a DNSBL address, refresh A without that DNSBL key, and require the withdrawn row to disappear;
- import the same address from feeds A and B, withdraw it from A, and require the row to remain because B still owns it;
- import an address from a feed, overwrite that address through the operator `/api/dnsbl` surface, withdraw the feed, and require the operator payload to survive at the domain-field level;
- reject feed overwrite of an operator-owned payload and report zero feed DNSBL writes for that skipped key.

`tests/threat_feed_dnsbl_persistence.rs` additionally covers restart-before-withdrawal, predecessor-state deserialization and persistence-failure rollback/retry. A solution that merely stops gateway scoring while leaving stale `/api/dnsbl` state, relies on TTL expiry, synthesizes hidden threat indicators, or keeps ownership only in process memory does not satisfy the contract.

The causal source repair was committed as `7042aa19267886e3af9c378dddd879929837877b`. Before that source-only commit was pushed, rescue run `34000662730` executed the resulting working tree: all locked workspace tests passed, including all four DNSBL ownership cases and all three persistence cases, and strict workspace Clippy passed. The workflow then verified that only `crates/waf-ids-core/src/lib.rs` and `src/lib.rs` were modified by the repair, removed both temporary repair workflows, and non-force pushed the causal commit. This is source-GREEN evidence, not a substitute for the required workflows on a later committed head.

## Protected-base compatibility and operational evidence

Protected `main` advanced independently through #171 to `a52ccd0a24a727d9349bb32def7713882d8cad1e`. A bounded non-force restack run `34000892973` checked the then-current #167 head, verified both the feature ref and protected-main SHA were unchanged, merged that exact protected head without rewriting history, removed its temporary restack workflow, and ran the full locked workspace tests plus strict workspace Clippy successfully before pushing merge commit `d8b452cf1d609bb6e9c9a8a33f265c0a32dce7c9`. Thus the causal Rust repair is candidate-base compatible with #171's protected truth.

The first standard required workflows on bot-authored source commit `7042aa1...` terminated `action_required` without jobs because that commit was produced by a `GITHUB_TOKEN` workflow; they are not GREEN evidence. A subsequent human-authored restack-control commit did trigger normal standard workflow materialization, with the Ubuntu CI lane entering the known queued class while the macOS restack runner acquired compute and completed. This narrows the runner evidence already handed to `.github#712`: the observed starvation is not an organization-wide inability to allocate any GitHub-hosted runner.

Merge remains prohibited until the unchanged final committed head obtains the then-live repository/security/review/governance evidence required by the protected ruleset. Queued, `action_required`, predecessor-head, or working-tree evidence must not be promoted to an exact-head required-gate verdict.

## Security rationale

This is a fail-safe lifecycle requirement. Revocation or withdrawal must converge the enforcement set toward less authority, not leave an orphaned deny decision whose producer no longer claims it. The rule also prevents one producer from deleting another producer's still-valid deny state and prevents automated feed refresh from erasing a later human/operator decision.

The general protection rationale remains the fail-safe-default principle documented for the adjacent MISP admission repair: authority must be established by explicit positive state, and ambiguous or withdrawn authority must not silently continue enforcement. See `docs/doctoring/misp-to-ids-admission.md` and its Saltzer–Schroeder traceability. The hostile regression style follows the repository's existing Manès et al. fuzzing-survey traceability and tests semantic lifecycle corruption rather than malformed JSON alone.

## Acceptance

The production behavior and causal source verification now satisfy these implementation criteria:

- `DnsblEntryKey` and its ownership fields are explicit, persisted, serde-defaulted, and tests cover predecessor-state deserialization;
- ownership replacement and stale-row removal happen inside the same `mutate_and_persist` transaction as the feed snapshot;
- same-address multiple-feed ownership prevents premature deletion;
- operator ownership prevents feed deletion and feed payload overwrite;
- persistence failure rolls ownership and effective state back before retry;
- repeated snapshots are idempotent at the domain-state level;
- `upserted_dnsbl` reports actual feed writes rather than requested input length when an operator-owned row is preserved;
- existing threat ownership semantics remain unchanged;
- no adapter-specific copy of reconciliation logic is introduced.

Release/merge acceptance remains separate: exact-current CI/Fuzz/security/coverage/SBOM/provenance/review/thread/governance evidence must be terminal-valid before protected merge, followed by fresh protected-head release evidence before any release-ready claim.
