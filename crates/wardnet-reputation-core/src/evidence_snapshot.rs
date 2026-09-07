//! Immutable source-generation membership for admitted reputation evidence.
//!
//! `EvidenceRecordV1` deliberately preserves producer evidence without claiming which completed
//! source refresh admitted it. The snapshot aggregate binds each retained record to one exact
//! `SourceSnapshotV1.source_generation` so an older record cannot be replayed into a newer
//! completed generation merely because the stable source identifier is unchanged.

use serde::{Deserialize, Serialize};

use crate::model::{
    BaseEvidenceSnapshotV1, ContractValidationErrorV1, EvidenceRecordV1, REPUTATION_SCHEMA_V1,
    SourceSnapshotV1,
};

const MAX_SOURCE_GENERATION_BYTES_V1: usize = 1_024;

/// Apply the v1 required-text bound before an admitted generation participates in matching.
fn validate_admitted_source_generation(
    source_generation: &str,
) -> Result<(), ContractValidationErrorV1> {
    if source_generation.trim().is_empty() {
        return Err(ContractValidationErrorV1::BlankField(
            "snapshot_record.source_generation",
        ));
    }
    if source_generation.len() > MAX_SOURCE_GENERATION_BYTES_V1 {
        return Err(ContractValidationErrorV1::BoundExceeded(
            "snapshot_record.source_generation",
        ));
    }
    Ok(())
}

/// Apply the v1 source-generation bound to an optional compare-and-swap expectation.
fn validate_expected_previous_source_generation(
    source_generation: Option<&str>,
) -> Result<(), ContractValidationErrorV1> {
    let Some(source_generation) = source_generation else {
        return Ok(());
    };
    if source_generation.trim().is_empty() {
        return Err(ContractValidationErrorV1::BlankField(
            "source_replacement.expected_previous_source_generation",
        ));
    }
    if source_generation.len() > MAX_SOURCE_GENERATION_BYTES_V1 {
        return Err(ContractValidationErrorV1::BoundExceeded(
            "source_replacement.expected_previous_source_generation",
        ));
    }
    Ok(())
}

/// One admitted evidence record plus the exact completed source generation that admitted it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvidenceSnapshotRecordV1 {
    /// Exact immutable source generation from which this record was admitted.
    pub source_generation: String,
    /// Versioned producer evidence retained by Wardnet.
    pub record: EvidenceRecordV1,
}

/// Explicit completeness state for one authenticated source replacement batch.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SourceBatchCompletenessV1 {
    /// The authenticated batch represents the complete source generation, including empty state.
    Complete,
    /// The batch is partial, truncated, or otherwise not safe to publish as a complete generation.
    Incomplete,
}

/// One authenticated complete-source candidate for atomic replacement in an evidence snapshot.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SourceReplacementBatchV1 {
    /// Contract schema identifier.
    pub schema_version: String,
    /// Explicit producer/admission completeness assertion; only `complete` may replace state.
    pub completeness: SourceBatchCompletenessV1,
    /// Exact prior source generation expected by the caller, or `None` for source creation.
    pub expected_previous_source_generation: Option<String>,
    /// Completed source generation that will replace or create the represented source.
    pub source_snapshot: SourceSnapshotV1,
    /// Complete set of records admitted from exactly `source_snapshot.source_generation`.
    pub records: Vec<EvidenceSnapshotRecordV1>,
}

/// Fail-closed errors for atomic source-generation replacement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceReplacementErrorV1 {
    /// A partial/truncated source batch can never replace the last-known-good generation.
    IncompleteSourceBatch,
    /// Batch records do not all belong to the batch's exact source and generation.
    SourceReplacementIdentityMismatch,
    /// Create/replace compare-and-swap expectation does not match the represented prior state.
    PreviousSourceGenerationMismatch,
    /// An existing source attempted to publish changed state under its prior immutable generation.
    ReusedSourceGeneration,
    /// A changed immutable snapshot attempted to reuse the prior Wardnet evidence generation.
    ReusedEvidenceGeneration,
    /// The resulting immutable snapshot violates an existing v1 contract invariant.
    Contract(ContractValidationErrorV1),
}

impl From<ContractValidationErrorV1> for SourceReplacementErrorV1 {
    fn from(value: ContractValidationErrorV1) -> Self {
        Self::Contract(value)
    }
}

/// Immutable aggregate proving complete source generations and exact record membership.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvidenceSnapshotV1 {
    /// Contract schema identifier.
    pub schema_version: String,
    /// Immutable Wardnet evidence generation identifier.
    pub evidence_generation: String,
    /// Completed source generations represented by this aggregate.
    pub source_snapshots: Vec<SourceSnapshotV1>,
    /// Bounded evidence records bound to the exact represented source generation that admitted them.
    pub records: Vec<EvidenceSnapshotRecordV1>,
}

impl EvidenceSnapshotV1 {
    /// Validate aggregate completeness, exact source-generation membership, and replay-safe identity.
    ///
    /// The pre-existing aggregate validator remains the single authority for v1 schema, source
    /// snapshot/record text bounds, list bounds, source uniqueness, record validation, completion
    /// ordering, and producer-record replay checks. This wrapper validates its own admission-only
    /// generation field before matching, then adds only the missing exact-generation invariant.
    pub fn validate_at(&self, now_unix: u64) -> Result<(), ContractValidationErrorV1> {
        for member in &self.records {
            validate_admitted_source_generation(&member.source_generation)?;
        }

        let base_snapshot = BaseEvidenceSnapshotV1 {
            schema_version: self.schema_version.clone(),
            evidence_generation: self.evidence_generation.clone(),
            source_snapshots: self.source_snapshots.clone(),
            records: self
                .records
                .iter()
                .map(|member| member.record.clone())
                .collect(),
        };
        base_snapshot.validate_at(now_unix)?;

        for member in &self.records {
            let has_exact_completed_generation = self.source_snapshots.iter().any(|snapshot| {
                snapshot.source_id == member.record.source_id
                    && snapshot.source_generation == member.source_generation
            });
            if !has_exact_completed_generation {
                return Err(ContractValidationErrorV1::MissingSourceSnapshot);
            }
        }

        Ok(())
    }

    /// Atomically replace one source with an authenticated complete generation.
    ///
    /// The method is pure: it never mutates the prior snapshot. Replacement is compare-and-swap
    /// bound to the exact prior source generation (or source absence for creation), without trying
    /// to order opaque generation identifiers. Existing sources must publish a distinct immutable
    /// generation identity. A complete empty generation is valid and removes only the prior records
    /// owned by that source. The constructed candidate is then delegated to [`Self::validate_at`]
    /// so existing list, schema, time, duplicate, provenance, lifecycle, and exact-generation
    /// invariants remain authoritative.
    pub fn replace_source(
        &self,
        replacement: SourceReplacementBatchV1,
        next_evidence_generation: &str,
        now_unix: u64,
    ) -> Result<Self, SourceReplacementErrorV1> {
        if replacement.completeness != SourceBatchCompletenessV1::Complete {
            return Err(SourceReplacementErrorV1::IncompleteSourceBatch);
        }

        self.validate_at(now_unix)?;
        if replacement.schema_version != REPUTATION_SCHEMA_V1 {
            return Err(ContractValidationErrorV1::UnsupportedSchema.into());
        }
        validate_expected_previous_source_generation(
            replacement.expected_previous_source_generation.as_deref(),
        )?;
        replacement.source_snapshot.validate_at(now_unix)?;

        if next_evidence_generation == self.evidence_generation {
            return Err(SourceReplacementErrorV1::ReusedEvidenceGeneration);
        }

        let source_id = replacement.source_snapshot.source_id.as_str();
        let source_generation = replacement.source_snapshot.source_generation.as_str();
        if replacement.records.iter().any(|member| {
            member.record.source_id != source_id || member.source_generation != source_generation
        }) {
            return Err(SourceReplacementErrorV1::SourceReplacementIdentityMismatch);
        }

        let prior_source = self
            .source_snapshots
            .iter()
            .find(|snapshot| snapshot.source_id == source_id);
        let prior_generation = prior_source.map(|snapshot| snapshot.source_generation.as_str());
        if prior_generation != replacement.expected_previous_source_generation.as_deref() {
            return Err(SourceReplacementErrorV1::PreviousSourceGenerationMismatch);
        }
        if prior_generation.is_some_and(|prior_generation| prior_generation == source_generation) {
            return Err(SourceReplacementErrorV1::ReusedSourceGeneration);
        }

        let mut source_snapshots =
            Vec::with_capacity(self.source_snapshots.len() + usize::from(prior_source.is_none()));
        source_snapshots.extend(
            self.source_snapshots
                .iter()
                .filter(|snapshot| snapshot.source_id != source_id)
                .cloned(),
        );

        let retained_record_count = self
            .records
            .iter()
            .filter(|member| member.record.source_id != source_id)
            .count();
        let mut records = Vec::with_capacity(retained_record_count + replacement.records.len());
        records.extend(
            self.records
                .iter()
                .filter(|member| member.record.source_id != source_id)
                .cloned(),
        );
        records.extend(replacement.records);
        source_snapshots.push(replacement.source_snapshot);

        let candidate = Self {
            schema_version: self.schema_version.clone(),
            evidence_generation: next_evidence_generation.to_owned(),
            source_snapshots,
            records,
        };
        candidate.validate_at(now_unix)?;
        Ok(candidate)
    }
}
