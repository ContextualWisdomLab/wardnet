# MISP threat-level severity translation

## Decision boundary

Wardnet imports MISP events through an anti-corruption layer before selected attributes become `ThreatIndicator` or `DnsblEntry` enforcement material. `Event.threat_level_id` is therefore an external semantic code that must be translated without strengthening the producer's assertion.

The live MISP source defines the enum as `1 = High`, `2 = Medium`, `3 = Low`, `4 = Undefined`. MISP's own CLI usage and canonical dashboard adapter encode that ordering explicitly. Wardnet previously documented the same enum but treated the values as though they were an internal ordinal: `1 -> Critical`, `2 -> High`, `3 -> Medium`. That deterministic one-tier inflation was rejected because a translation boundary must not manufacture stronger threat evidence than the source supplied.

Wardnet now maps defined MISP values exactly: `1 -> High`, `2 -> Medium`, and `3 -> Low`. MISP `4 = Undefined` remains conservatively represented as Wardnet `Low` because the current Wardnet `Severity` enum has no `Undefined` member; this is a compatibility representation, not an assertion that MISP classified the event as Low. Missing or structurally unrecognized `threat_level_id` retains the pre-existing MISP-level-2 compatibility fallback and therefore maps to Wardnet `Medium`. A future domain-model change may introduce an explicit unknown/undefined severity, but that requires a separate aggregate/API compatibility decision rather than silently overloading this adapter repair.

The change does not alter the independent MISP admission invariants in [`misp-to-ids-admission.md`](misp-to-ids-admission.md): `to_ids` must be affirmative and recognized, and withdrawn or structurally invalid lifecycle state must not authorize enforcement.

## Alternatives considered

Keeping the shifted mapping was rejected because it changes the meaning of MISP authority data and can distort SOC prioritization, policy evaluation, audit evidence, and downstream provenance. Mapping MISP `4 = Undefined` to `Critical` or `Medium` was rejected because no such source assertion exists. Rejecting every event with undefined or absent threat level was also rejected in this bounded fix because the existing import contract already accepts those events and there is no explicit Wardnet `Undefined` severity today; changing admission compatibility belongs in a separate versioned decision.

## Verification contract

`tests/misp_threat_level_severity.rs` is the focused contract regression. It submits otherwise admissible MISP events using both string and numeric representations and requires `threat_level_id` 1, 2, and 3 to produce exactly `Severity::High`, `Severity::Medium`, and `Severity::Low`. RED `45c5c2d0fc87cf6897eabaed032231fb589185e8` preceded production GREEN `1502edf1cff801b1e4d31dfab1d4a0aad89ef489`; the inherited implementation returned Critical/High/Medium for the three defined source levels. Existing `to_ids`, deletion-state, shared DNSBL ownership, restart and persistence regressions remain inherited from the parent rather than copied into this adapter.

The child has now non-force adopted the complete stable parent lineage. Parent exact `0c83cd5956f512d79c6600e823fcfa6d6f32af4e` already contains the shared DNSBL reconciliation source GREEN and protected-main adoption. Temporary child-restack run `34001140916` pinned that parent and the triggering child ref, merged the parent without rewriting history, formatted only the two expected severity-code/test files under the pinned Rust toolchain, ran full locked workspace tests and strict workspace Clippy successfully, removed the temporary workflow, and proved the final child-versus-parent delta is exactly three files: this decision record, `src/misp_import.rs`, and `tests/misp_threat_level_severity.rs`. The resulting two-parent merge is `e0a7d9034b8810fc4284beb57f990eb2c3ab7641`.

That restack proves source/candidate compatibility, not protected merge readiness. Standard repository/security/review workflows must be acquired on the final human-authored exact head; queued, `action_required`, predecessor-head or temporary-workflow results cannot be promoted as exact-head gate evidence.

## Traceability and references

MISP Project. (n.d.). *CLI usage: Event threat level*. GitHub. https://github.com/MISP/MISP/blob/9294667a5b40e59ea42314c2aafa99086ce1d8e6/app/Console/Command/CLI_usage.md

MISP Project. (n.d.). *CanonicalTypeAdapter: MISP threat-level filter*. GitHub. https://github.com/MISP/MISP/blob/9294667a5b40e59ea42314c2aafa99086ce1d8e6/app/Lib/Dashboard/Tools/CanonicalTypeAdapter.php

MISP Project. (2015, November 24). *Threat level coding misleading* (Issue #729). GitHub. https://github.com/MISP/MISP/issues/729
