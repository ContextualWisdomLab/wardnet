//! Pure Wardnet outbound site-reputation contracts.
//!
//! This crate deliberately performs no HTTP, DNS, transport authorization, database I/O,
//! environment access, or LLM work. Executable outbound target interpretation remains an
//! EgressWeave responsibility; this crate only accepts already-canonical offline descriptors.
//!
//! The research, standards, rejected alternatives, and evidence-handling rationale for this
//! contract boundary are recorded in the adjacent [TRACEABILITY.md](../TRACEABILITY.md).

mod evidence_snapshot;
pub mod live_validation;
pub mod model;

pub use evidence_snapshot::*;
pub use live_validation::*;
pub use model::{
    BusinessAuthorizationBindingV1, ContractValidationErrorV1, DecisionEnvelopeV1,
    DecisionReasonV1, DestinationContextV1, DestinationScopeV1, DestinationSubjectKindV1,
    DestinationSubjectV1, DirectionV1, EvaluationModeV1, EvidenceClassificationV1,
    EvidenceHealthV1, EvidenceRecordV1, PolicyActionV1, PolicySnapshotV1, REPUTATION_SCHEMA_V1,
    ReputationAssessmentV1, SourcePolicyV1, SourceSnapshotV1, SourceTenantScopeV1,
};
