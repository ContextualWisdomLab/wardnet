//! Monotonic producer-record lifecycle admission for immutable reputation evidence.
//!
//! Producer version tokens are intentionally opaque. Source adapters authenticate source-specific
//! ordering semantics and supply the normalized monotonic ordinal used by this pure contract.

use crate::{ContractValidationErrorV1, EvidenceRecordV1, REPUTATION_SCHEMA_V1};

const MAX_LIFECYCLE_ID_BYTES_V1: usize = 1_024;

/// Fail-closed producer lifecycle admission errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProducerLifecycleValidationErrorV1 {
    /// The candidate evidence record violates the existing reputation contract.
    Contract(ContractValidationErrorV1),
    /// Candidate source or producer-record identity differs from the retained cursor.
    LifecycleIdentityMismatch,
    /// Candidate normalized producer version is older than the retained version.
    StaleProducerRecordVersion,
    /// One normalized ordinal maps to a different opaque producer version token.
    ProducerRecordVersionCollision,
    /// A terminal tombstoned producer-record identity attempts to become active again.
    TombstoneResurrection,
}

impl From<ContractValidationErrorV1> for ProducerLifecycleValidationErrorV1 {
    fn from(value: ContractValidationErrorV1) -> Self {
        Self::Contract(value)
    }
}

/// Bounded retained lifecycle state for one exact producer record identity.
///
/// This value is deterministic admission state, not authenticated persistence or producer proof.
/// A source adapter is responsible for deriving `producer_version_ordinal` from authenticated
/// source semantics without guessing ordering from the opaque producer version token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProducerRecordLifecycleCursorV1 {
    /// Reputation contract schema identifier.
    pub schema_version: String,
    /// Exact producer source identifier.
    pub source_id: String,
    /// Exact producer record identifier.
    pub producer_record_id: String,
    /// Opaque producer version token associated with the retained ordinal.
    pub producer_record_version: String,
    /// Source-adapter-normalized monotonic version ordinal.
    pub producer_version_ordinal: u64,
    /// Whether this producer record identity has reached terminal withdrawn state.
    pub tombstoned: bool,
}

impl ProducerRecordLifecycleCursorV1 {
    /// Validate the retained cursor and admit one candidate producer version.
    ///
    /// Tombstones are terminal for the exact `(source_id, producer_record_id)` identity. A producer
    /// that legitimately reintroduces evidence must issue a new record identity or a separately
    /// reviewed source-specific lifecycle contract.
    pub fn admit(
        &self,
        candidate: &EvidenceRecordV1,
        candidate_ordinal: u64,
        now_unix: u64,
    ) -> Result<Self, ProducerLifecycleValidationErrorV1> {
        self.validate()?;
        candidate.validate_at(now_unix)?;

        if candidate.source_id != self.source_id
            || candidate.producer_record_id != self.producer_record_id
        {
            return Err(ProducerLifecycleValidationErrorV1::LifecycleIdentityMismatch);
        }
        if candidate_ordinal < self.producer_version_ordinal {
            return Err(ProducerLifecycleValidationErrorV1::StaleProducerRecordVersion);
        }
        if candidate_ordinal == self.producer_version_ordinal
            && candidate.producer_record_version != self.producer_record_version
        {
            return Err(ProducerLifecycleValidationErrorV1::ProducerRecordVersionCollision);
        }

        let candidate_tombstoned = candidate.revoked || candidate.deleted;
        if self.tombstoned && !candidate_tombstoned {
            return Err(ProducerLifecycleValidationErrorV1::TombstoneResurrection);
        }

        Ok(Self {
            schema_version: REPUTATION_SCHEMA_V1.to_owned(),
            source_id: candidate.source_id.clone(),
            producer_record_id: candidate.producer_record_id.clone(),
            producer_record_version: candidate.producer_record_version.clone(),
            producer_version_ordinal: candidate_ordinal,
            tombstoned: candidate_tombstoned,
        })
    }

    fn validate(&self) -> Result<(), ProducerLifecycleValidationErrorV1> {
        if self.schema_version != REPUTATION_SCHEMA_V1 {
            return Err(ContractValidationErrorV1::UnsupportedSchema.into());
        }
        validate_required_text(&self.source_id, "source_id")?;
        validate_required_text(&self.producer_record_id, "producer_record_id")?;
        validate_required_text(&self.producer_record_version, "producer_record_version")?;
        Ok(())
    }
}

fn validate_required_text(
    value: &str,
    field: &'static str,
) -> Result<(), ProducerLifecycleValidationErrorV1> {
    if value.trim().is_empty() {
        return Err(ContractValidationErrorV1::BlankField(field).into());
    }
    if value.len() > MAX_LIFECYCLE_ID_BYTES_V1 {
        return Err(ContractValidationErrorV1::BoundExceeded(field).into());
    }
    Ok(())
}
