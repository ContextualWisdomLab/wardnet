# Threat-feed DNSBL snapshot ownership

## Decision boundary

`POST /api/threat-feeds/import` is a snapshot-reconciliation boundary, not an append-only DNSBL ingest path. A feed refresh may withdraw a previously published address. Wardnet must therefore distinguish four facts that the current global `Vec<DnsblEntry>` cannot express by itself:

1. the stable DNSBL identity currently used by `upsert_dnsbl`;
2. which feed snapshots still claim that identity;
3. whether an operator independently owns that identity; and
4. the current effective payload stored for that identity.

The stable identity for this repair is the same identity the mutation primitive already enforces: IP `address`. Introducing a different ownership key would make reconciliation disagree with `upsert_dnsbl` and would permit two logical owners to mutate one physical row under incompatible identities.

## Required state model

The durable `AppData` authority must carry explicit DNSBL ownership rather than infer it from source strings, TTL, threat indicators, audit logs, or adapter-specific conventions.

- Add a serializable/hashable `DnsblEntryKey` whose identity matches the global DNSBL upsert identity.
- Add `dnsbl_keys` to each `ThreatFeedOwnership`, with `#[serde(default)]` so persisted predecessor state migrates without a destructive rewrite.
- Add `operator_dnsbl_keys` to `AppData`, also `#[serde(default)]`.
- `/api/dnsbl` writes mark the address as operator-owned before replacing the effective DNSBL payload.
- A feed import replaces that feed's threat and DNSBL ownership sets as one snapshot mutation, then removes each previously-owned DNSBL row only when the address is absent from the new snapshot, absent from every other feed ownership set, and absent from operator ownership.
- Feed upsert must not overwrite an operator-owned payload at the same stable address. This mirrors the existing threat-indicator rule that operator-managed payload wins over feed refresh.

Ownership metadata is internal control-plane state. It does not become threat intelligence, does not become a synthetic `ThreatIndicator`, and must not be encoded into `source`, audit-log text, or another bounded context. Those shortcuts were rejected because they would make authority implicit and break DDD naming/semantic boundaries.

## Replay, persistence, and idempotency

A repeated identical feed snapshot must leave both ownership and effective DNSBL state unchanged apart from the feed freshness timestamp already owned by the import path. Restarting from persisted `AppData` must retain enough ownership to make the next refresh deterministic; an in-memory sidecar is therefore not sufficient. A refresh of feed A must never delete an address still owned by feed B. A later operator upsert at an address previously owned by a feed must survive withdrawal of that feed without payload rollback.

The repair must remain inside Wardnet's shared threat-feed admission/control-plane path. MISP, STIX/TAXII, OpenCTI, KEV, and other adapters provide feed material but do not copy or reimplement reconciliation. This is why the valid review finding is repaired at `apply_threat_feed_import`, not inside `misp_import.rs`.

## Hostile RED contract

`tests/threat_feed_dnsbl_ownership.rs` is the focused public-API regression. Exact RED `a639e626764e2caf593266dbf94d2b030626bbaf` proves the current state model lacks the first required cleanup behavior and cannot safely prove operator ownership:

- import feed A with one DNSBL address, refresh A with an empty DNSBL snapshot, and require the withdrawn row to disappear;
- import the same address from feeds A and B, withdraw it from A, and require the row to remain because B still owns it;
- import an address from a feed, overwrite that address through the operator `/api/dnsbl` surface, withdraw the feed, and require the operator payload to survive byte-for-byte at the domain-field level.

GREEN requires all three tests plus existing threat-feed ownership regressions to pass on the same exact head. A solution that merely stops gateway scoring while leaving stale `/api/dnsbl` state, relies on TTL expiry, synthesizes hidden threat indicators, or keeps ownership only in process memory does not satisfy the contract.

## Operational evidence

The current central runner queue can delay remote execution, but queued/pre-checkout state is non-passing evidence rather than a reason to weaken this invariant. Merge remains prohibited until the exact repaired head obtains the repository-owned CI/Fuzz and all then-live security, coverage, SBOM, provenance, review-thread, and branch-integrity gates required by the protected ruleset.

## Security rationale

This is a fail-safe lifecycle requirement. Revocation or withdrawal must converge the enforcement set toward less authority, not leave an orphaned deny decision whose producer no longer claims it. The rule also prevents one producer from deleting another producer's still-valid deny state and prevents automated feed refresh from erasing a later human/operator decision.

The general protection rationale remains the fail-safe-default principle documented for the adjacent MISP admission repair: authority must be established by explicit positive state, and ambiguous or withdrawn authority must not silently continue enforcement. See `docs/doctoring/misp-to-ids-admission.md` and its Saltzer–Schroeder traceability. The hostile regression style follows the repository's existing Manès et al. fuzzing-survey traceability and tests semantic lifecycle corruption rather than malformed JSON alone.

## Acceptance

- `DnsblEntryKey` and its ownership fields are explicit, persisted, serde-defaulted, and code/API tests cover predecessor-state deserialization.
- ownership replacement and stale-row removal happen inside the same `mutate_and_persist` transaction as the feed snapshot;
- same-address multiple-feed ownership prevents premature deletion;
- operator ownership prevents feed deletion and feed payload overwrite;
- repeated snapshots are idempotent;
- `upserted_dnsbl` reports actual feed writes, not merely requested input length when an operator-owned row is preserved;
- existing threat ownership semantics remain unchanged;
- no adapter-specific copy of reconciliation logic is introduced;
- exact-current CI/Fuzz/security/coverage/SBOM/provenance/review evidence is terminal GREEN before merge.
