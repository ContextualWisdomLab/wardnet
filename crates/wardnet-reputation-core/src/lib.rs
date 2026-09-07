//! Pure Wardnet outbound site-reputation contracts.
//!
//! This crate deliberately performs no HTTP, DNS, transport authorization, database I/O,
//! environment access, or LLM work. Executable outbound target interpretation remains an
//! EgressWeave responsibility; this crate only accepts already-canonical offline descriptors.
//!
//! The generation-bound evidence snapshot is the sole public v1 snapshot authority. The
//! superseded unbound aggregate must not remain constructible through the compatibility module:
//!
//! ```compile_fail
//! use wardnet_reputation_core::model::EvidenceSnapshotV1;
//! ```
//!
//! The research, standards, rejected alternatives, and evidence-handling rationale for this
//! contract boundary are recorded in the adjacent [TRACEABILITY.md](../TRACEABILITY.md). Exact
//! source-generation membership and its hostile replay evidence are recorded in
//! [SOURCE_GENERATION_TRACEABILITY.md](../SOURCE_GENERATION_TRACEABILITY.md).

mod evidence_snapshot;
pub mod live_validation;
#[path = "model.rs"]
mod model_impl;

/// Compatibility namespace for the unaffected v1 model contracts.
///
/// The generation-unbound snapshot aggregate is intentionally excluded because
/// [`EvidenceSnapshotV1`] is now the sole public snapshot authority.
pub mod model {
    pub use super::model_impl::{
        BusinessAuthorizationBindingV1, ContractValidationErrorV1, DecisionEnvelopeV1,
        DecisionReasonV1, DestinationContextV1, DestinationScopeV1, DestinationSubjectKindV1,
        DestinationSubjectV1, DirectionV1, EvaluationModeV1, EvidenceClassificationV1,
        EvidenceHealthV1, EvidenceRecordV1, PolicyActionV1, PolicySnapshotV1,
        REPUTATION_SCHEMA_V1, ReputationAssessmentV1, SourcePolicyV1, SourceSnapshotV1,
        SourceTenantScopeV1,
    };
    pub(crate) use super::model_impl::EvidenceSnapshotV1 as BaseEvidenceSnapshotV1;
}

pub use evidence_snapshot::*;
pub use live_validation::*;
pub use model::{
    BusinessAuthorizationBindingV1, ContractValidationErrorV1, DecisionEnvelopeV1,
    DecisionReasonV1, DestinationContextV1, DestinationScopeV1, DestinationSubjectKindV1,
    DestinationSubjectV1, DirectionV1, EvaluationModeV1, EvidenceClassificationV1,
    EvidenceHealthV1, EvidenceRecordV1, PolicyActionV1, PolicySnapshotV1, REPUTATION_SCHEMA_V1,
    ReputationAssessmentV1, SourcePolicyV1, SourceSnapshotV1, SourceTenantScopeV1,
};
