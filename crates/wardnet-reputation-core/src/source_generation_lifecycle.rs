//! Monotonic admission state for immutable source-generation replacement.
//!
//! Source-generation identifiers are opaque producer tokens. Wardnet never infers ordering from
//! their text. Instead, the source adapter supplies an authenticated normalized ordinal and this
//! module enforces monotonicity, token/ordinal collision safety, source identity, completion-time
//! monotonicity, and exact coupling to the currently represented evidence snapshot.

use serde::{Deserialize, Serialize};

use crate::evidence_snapshot::{
    EvidenceSnapshotV1, SourceReplacementBatchV1, SourceReplacementErrorV1,
};
use crate::model::{ContractValidationErrorV1, SourceSnapshotV1};

/// Retained admission cursor for one immutable source-generation stream.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SourceGenerationLifecycleCursorV1 {
    /// Contract schema identifier retained with the cursor.
    pub schema_version: String,
    /// Stable source identity whose generations this cursor governs.
    pub source_id: String,
    /// Most recently admitted opaque immutable source-generation token.
    pub source_generation: String,
    /// Adapter-authenticated normalized monotonic ordinal for the admitted generation.
    pub source_generation_ordinal: u64,
    /// Authenticated completion point of the admitted generation.
    pub completed_at_unix: u64,
}

/// Fail-closed errors for source-generation lifecycle admission and bound replacement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceGenerationLifecycleErrorV1 {
    /// A cursor or candidate violates an existing bounded v1 contract invariant.
    Contract(ContractValidationErrorV1),
    /// The retained cursor does not exactly describe the source generation represented by snapshot.
    SnapshotCursorMismatch,
    /// A candidate attempted to substitute another stable source identity.
    LifecycleIdentityMismatch,
    /// The adapter-authenticated ordinal moved backwards.
    StaleSourceGenerationOrdinal,
    /// One ordinal was rebound to a different opaque source-generation token.
    SourceGenerationOrdinalCollision,
    /// A previously admitted opaque generation token was reused or rebound to another ordinal.
    ReusedSourceGeneration,
    /// A newer generation moved the authenticated completion point backwards.
    SourceCompletionRegression,
    /// Existing complete-source replacement validation rejected the candidate snapshot.
    Replacement(SourceReplacementErrorV1),
}

impl From<ContractValidationErrorV1> for SourceGenerationLifecycleErrorV1 {
    fn from(value: ContractValidationErrorV1) -> Self {
        Self::Contract(value)
    }
}

impl From<SourceReplacementErrorV1> for SourceGenerationLifecycleErrorV1 {
    fn from(value: SourceReplacementErrorV1) -> Self {
        Self::Replacement(value)
    }
}

/// Successful pure replacement result that advances snapshot and source cursor together.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceReplacementTransitionV1 {
    /// Next immutable Wardnet evidence snapshot.
    pub evidence_snapshot: EvidenceSnapshotV1,
    /// Next retained lifecycle cursor for the replaced source.
    pub source_generation_cursor: SourceGenerationLifecycleCursorV1,
}

impl SourceGenerationLifecycleCursorV1 {
    /// Validate cursor schema, bounded identities, and completion time using the source contract.
    pub fn validate_at(&self, now_unix: u64) -> Result<(), ContractValidationErrorV1> {
        SourceSnapshotV1 {
            schema_version: self.schema_version.clone(),
            source_id: self.source_id.clone(),
            source_generation: self.source_generation.clone(),
            completed_at_unix: self.completed_at_unix,
            valid_until_unix: self.completed_at_unix,
        }
        .validate_at(now_unix)
    }

    /// Admit one candidate generation using an adapter-authenticated normalized ordinal.
    ///
    /// Opaque source-generation text is compared only for exact identity/collision detection; it is
    /// never sorted. Lower ordinals are stale, the same ordinal cannot name another token, and a
    /// prior token cannot be rebound at a later ordinal.
    pub fn admit(
        &self,
        candidate: &SourceSnapshotV1,
        candidate_ordinal: u64,
        now_unix: u64,
    ) -> Result<Self, SourceGenerationLifecycleErrorV1> {
        self.validate_at(now_unix)?;
        candidate.validate_at(now_unix)?;

        if candidate.source_id != self.source_id {
            return Err(SourceGenerationLifecycleErrorV1::LifecycleIdentityMismatch);
        }
        if candidate.completed_at_unix < self.completed_at_unix {
            return Err(SourceGenerationLifecycleErrorV1::SourceCompletionRegression);
        }
        if candidate_ordinal < self.source_generation_ordinal {
            return Err(SourceGenerationLifecycleErrorV1::StaleSourceGenerationOrdinal);
        }
        if candidate_ordinal == self.source_generation_ordinal {
            if candidate.source_generation != self.source_generation {
                return Err(SourceGenerationLifecycleErrorV1::SourceGenerationOrdinalCollision);
            }
            return Err(SourceGenerationLifecycleErrorV1::ReusedSourceGeneration);
        }
        if candidate.source_generation == self.source_generation {
            return Err(SourceGenerationLifecycleErrorV1::ReusedSourceGeneration);
        }

        Ok(Self {
            schema_version: candidate.schema_version.clone(),
            source_id: candidate.source_id.clone(),
            source_generation: candidate.source_generation.clone(),
            source_generation_ordinal: candidate_ordinal,
            completed_at_unix: candidate.completed_at_unix,
        })
    }

    /// Construct the first retained cursor for a newly represented source.
    fn initial(
        candidate: &SourceSnapshotV1,
        candidate_ordinal: u64,
        now_unix: u64,
    ) -> Result<Self, SourceGenerationLifecycleErrorV1> {
        candidate.validate_at(now_unix)?;
        Ok(Self {
            schema_version: candidate.schema_version.clone(),
            source_id: candidate.source_id.clone(),
            source_generation: candidate.source_generation.clone(),
            source_generation_ordinal: candidate_ordinal,
            completed_at_unix: candidate.completed_at_unix,
        })
    }
}

impl EvidenceSnapshotV1 {
    /// Replace one complete source generation while advancing its retained replay cursor atomically.
    ///
    /// This is a pure domain transition, not a durable transaction. For an existing source, the
    /// retained cursor must exactly match the source identity, generation token, and completion
    /// point represented by `self` before the candidate may advance. Source creation requires no
    /// retained cursor. Only after lifecycle admission succeeds does the existing complete-source
    /// replacement authority build and validate the next immutable snapshot; the method returns the
    /// next snapshot and next cursor together so callers cannot accidentally advance only one.
    pub fn replace_source_with_lifecycle(
        &self,
        retained_cursor: Option<&SourceGenerationLifecycleCursorV1>,
        replacement: SourceReplacementBatchV1,
        candidate_ordinal: u64,
        next_evidence_generation: &str,
        now_unix: u64,
    ) -> Result<SourceReplacementTransitionV1, SourceGenerationLifecycleErrorV1> {
        self.validate_at(now_unix)?;

        let candidate_source = &replacement.source_snapshot;
        let represented_source = self
            .source_snapshots
            .iter()
            .find(|snapshot| snapshot.source_id == candidate_source.source_id);

        let next_cursor = match (represented_source, retained_cursor) {
            (Some(represented), Some(cursor)) => {
                cursor.validate_at(now_unix)?;
                if cursor.source_id != represented.source_id
                    || cursor.source_generation != represented.source_generation
                    || cursor.completed_at_unix != represented.completed_at_unix
                {
                    return Err(SourceGenerationLifecycleErrorV1::SnapshotCursorMismatch);
                }
                cursor.admit(candidate_source, candidate_ordinal, now_unix)?
            }
            (None, None) => SourceGenerationLifecycleCursorV1::initial(
                candidate_source,
                candidate_ordinal,
                now_unix,
            )?,
            _ => return Err(SourceGenerationLifecycleErrorV1::SnapshotCursorMismatch),
        };

        let evidence_snapshot =
            self.replace_source(replacement, next_evidence_generation, now_unix)?;

        Ok(SourceReplacementTransitionV1 {
            evidence_snapshot,
            source_generation_cursor: next_cursor,
        })
    }
}
