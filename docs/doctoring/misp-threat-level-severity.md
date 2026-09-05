# MISP threat-level severity translation

## Decision boundary

Wardnet imports MISP events through an anti-corruption layer before selected attributes become `ThreatIndicator` or `DnsblEntry` enforcement material. `Event.threat_level_id` is therefore an external semantic code that must be translated without strengthening the producer's assertion.

The live MISP source defines the enum as `1 = High`, `2 = Medium`, `3 = Low`, `4 = Undefined`. MISP's own CLI usage and canonical dashboard adapter encode that ordering explicitly. Wardnet previously documented the same enum but treated the values as though they were an internal ordinal: `1 -> Critical`, `2 -> High`, `3 -> Medium`. That deterministic one-tier inflation was rejected because a translation boundary must not manufacture stronger threat evidence than the source supplied.

Wardnet now maps defined MISP values exactly: `1 -> High`, `2 -> Medium`, and `3 -> Low`. MISP `4 = Undefined` remains conservatively represented as Wardnet `Low` because the current Wardnet `Severity` enum has no `Undefined` member; this is a compatibility representation, not an assertion that MISP classified the event as Low. Missing or structurally unrecognized `threat_level_id` retains the pre-existing MISP-level-2 compatibility fallback and therefore maps to Wardnet `Medium`. A future domain-model change may introduce an explicit unknown/undefined severity, but that requires a separate aggregate/API compatibility decision rather than silently overloading this adapter repair.

The change does not alter the independent MISP admission invariants in [`misp-to-ids-admission.md`](misp-to-ids-admission.md): `to_ids` must be affirmative and recognized, and withdrawn or structurally invalid lifecycle state must not authorize enforcement.

## Alternatives considered

Keeping the shifted mapping was rejected because it changes the meaning of MISP authority data and can distort SOC prioritization, policy evaluation, audit evidence, and downstream provenance. Mapping MISP `4 = Undefined` to `Critical` or `Medium` was rejected because no such source assertion exists. Rejecting every event with undefined or absent threat level was also rejected in this bounded fix because the existing import contract already accepts those events and there is no explicit Wardnet `Undefined` severity today; changing admission compatibility belongs in a separate versioned decision.

## Verification contract

`tests/misp_threat_level_severity.rs` is the focused contract regression. It submits otherwise admissible MISP events using both string and numeric representations and requires `threat_level_id` 1, 2, and 3 to produce exactly `Severity::High`, `Severity::Medium`, and `Severity::Low`. The test was committed before the production mapping changed, so the predecessor implementation fails by returning Critical/High/Medium. Existing `to_ids` and deletion-state tests continue to exercise the independent fail-closed admission boundary.

Merge evidence must be produced on the exact current stacked head after the parent MISP admission delta is fixed in ancestry. Predecessor checks, review comments, or a locally inferred source mapping do not transfer as release evidence.

## Traceability and references

MISP Project. (n.d.). *CLI usage: Event threat level*. GitHub. https://github.com/MISP/MISP/blob/9294667a5b40e59ea42314c2aafa99086ce1d8e6/app/Console/Command/CLI_usage.md

MISP Project. (n.d.). *CanonicalTypeAdapter: MISP threat-level filter*. GitHub. https://github.com/MISP/MISP/blob/9294667a5b40e59ea42314c2aafa99086ce1d8e6/app/Lib/Dashboard/Tools/CanonicalTypeAdapter.php

MISP Project. (2015, November 24). *Threat level coding misleading* (Issue #729). GitHub. https://github.com/MISP/MISP/issues/729
