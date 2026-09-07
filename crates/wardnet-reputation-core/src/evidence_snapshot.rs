//! Immutable source-generation membership for admitted reputation evidence.
//!
//! `EvidenceRecordV1` deliberately preserves producer evidence without claiming which completed
//! source refresh admitted it. The snapshot aggregate binds each retained record to one exact
//! `SourceSnapshotV1.source_generation` so an older record cannot be replayed into a newer
//! completed generation merely because the stable source identifier is unchanged.

use serde::{Deserialize, Serialize};

use crate::model::{
    BaseEvidenceSnapshotV1, ContractValidationErrorV1, EvidenceRecordV1, SourceSnapshotV1,
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

/// One admitted evidence record plus the exact completed source generation that admitted it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvidenceSnapshotRecordV1 {
    /// Exact immutable source generation from which this record was admitted.
    pub source_generation: String,
    /// Versioned producer evidence retained by Wardnet.
    pub record: EvidenceRecordV1,
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
}
