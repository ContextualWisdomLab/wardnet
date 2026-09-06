//! Versioned, transport-neutral outbound site-reputation domain contracts.

use serde::{Deserialize, Serialize};

/// Wire schema identifier for the first Wardnet reputation contract family.
pub const REPUTATION_SCHEMA_V1: &str = "wardnet.reputation.v1";

const MAX_TEXT_BYTES_V1: usize = 1_024;
const MAX_LIST_ITEMS_V1: usize = 64;

fn validate_schema(schema_version: &str) -> Result<(), ContractValidationErrorV1> {
    if schema_version == REPUTATION_SCHEMA_V1 {
        Ok(())
    } else {
        Err(ContractValidationErrorV1::UnsupportedSchema)
    }
}

fn validate_text(value: &str, field: &'static str) -> Result<(), ContractValidationErrorV1> {
    if value.trim().is_empty() {
        return Err(ContractValidationErrorV1::BlankField(field));
    }
    if value.len() > MAX_TEXT_BYTES_V1 {
        return Err(ContractValidationErrorV1::BoundExceeded(field));
    }
    Ok(())
}

fn validate_optional_text(
    value: Option<&str>,
    field: &'static str,
) -> Result<(), ContractValidationErrorV1> {
    if let Some(value) = value {
        validate_text(value, field)?;
    }
    Ok(())
}

fn validate_text_list(
    values: &[String],
    field: &'static str,
) -> Result<(), ContractValidationErrorV1> {
    if values.len() > MAX_LIST_ITEMS_V1 {
        return Err(ContractValidationErrorV1::BoundExceeded(field));
    }
    for value in values {
        validate_text(value, field)?;
    }
    Ok(())
}

/// Direction of the evaluated destination operation.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DirectionV1 {
    /// Outbound traffic from a protected workload toward an external destination.
    Outbound,
    /// Inbound traffic is represented so validation can reject it explicitly.
    Inbound,
}

/// Canonical subject kind supplied to Wardnet by an owning canonicalization boundary.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum DestinationSubjectKindV1 {
    /// Exact canonical host name.
    ExactHost,
    /// Exact visible canonical URL observable.
    ObservableUrl,
    /// Exact canonical actual address and port observable.
    ActualAddress,
}

/// Explicit matching scope for a canonical destination subject.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DestinationScopeV1 {
    /// Match exactly the supplied canonical subject.
    Exact,
    /// Match the exact host and dot-boundary subdomains only.
    HostAndSubdomains,
}

/// Canonical destination descriptor that Wardnet matches without reparsing network syntax.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DestinationSubjectV1 {
    /// Subject kind defining how the opaque canonical value may be matched.
    pub kind: DestinationSubjectKindV1,
    /// Canonical value produced by the owning canonicalization boundary.
    pub value: String,
    /// Explicit matching scope; non-host kinds must remain exact.
    pub scope: DestinationScopeV1,
}

impl DestinationSubjectV1 {
    fn validate(&self) -> Result<(), ContractValidationErrorV1> {
        validate_text(&self.value, "subject.value")?;
        if self.scope == DestinationScopeV1::HostAndSubdomains
            && self.kind != DestinationSubjectKindV1::ExactHost
        {
            return Err(ContractValidationErrorV1::AmbiguousSubjectScope);
        }
        Ok(())
    }
}

/// Authenticated evaluation context after identity claims have been verified by the service edge.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DestinationContextV1 {
    /// Contract schema identifier.
    pub schema_version: String,
    /// Evaluated direction; this contract accepts outbound only.
    pub direction: DirectionV1,
    /// Authenticated tenant identifier.
    pub tenant_id: String,
    /// Authenticated workload identifier.
    pub workload_id: String,
    /// Registered purpose identifier.
    pub purpose: String,
    /// Unique operation correlation identifier.
    pub operation_id: String,
    /// Reputation protection profile identifier.
    pub profile_id: String,
    /// Canonical destination subject.
    pub subject: DestinationSubjectV1,
    /// Canonicalization profile name owned outside this crate.
    pub canonicalization_profile: String,
    /// Canonicalization profile version owned outside this crate.
    pub canonicalization_version: String,
}

impl DestinationContextV1 {
    /// Validate the bounded contract shape without authenticating caller-controlled identity text.
    pub fn validate(&self) -> Result<(), ContractValidationErrorV1> {
        validate_schema(&self.schema_version)?;
        if self.direction != DirectionV1::Outbound {
            return Err(ContractValidationErrorV1::WrongDirection);
        }
        validate_text(&self.tenant_id, "tenant_id")?;
        validate_text(&self.workload_id, "workload_id")?;
        validate_text(&self.purpose, "purpose")?;
        validate_text(&self.operation_id, "operation_id")?;
        validate_text(&self.profile_id, "profile_id")?;
        self.subject.validate()?;
        validate_text(&self.canonicalization_profile, "canonicalization_profile")?;
        validate_text(&self.canonicalization_version, "canonicalization_version")?;
        Ok(())
    }
}

/// Security classification preserved from an eligible producer record.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceClassificationV1 {
    /// Producer evidence asserts a known malicious destination within its explicit scope.
    KnownMalicious,
    /// Producer evidence is adverse but not eligible to assert known maliciousness.
    Suspicious,
}

/// Versioned source evidence retained with lifecycle and provenance semantics.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceRecordV1 {
    /// Contract schema identifier.
    pub schema_version: String,
    /// Reviewed source policy identifier.
    pub source_id: String,
    /// Producer-native record identifier.
    pub producer_record_id: String,
    /// Producer-native monotonic or immutable record version identifier.
    pub producer_record_version: String,
    /// Canonical subject and explicit scope asserted by the producer mapping.
    pub subject: DestinationSubjectV1,
    /// Security classification preserved by the adapter.
    pub classification: EvidenceClassificationV1,
    /// Producer severity text, preserved rather than converted into a probability.
    pub producer_severity: Option<String>,
    /// Optional producer confidence on the producer's own 0-100 scale.
    pub producer_confidence: Option<u8>,
    /// Time the producer says the observation was made.
    pub observed_at_unix: u64,
    /// Time Wardnet received the authenticated producer record.
    pub received_at_unix: u64,
    /// Start of the producer validity interval.
    pub valid_from_unix: u64,
    /// End of the producer validity interval.
    pub valid_until_unix: u64,
    /// Producer lifecycle revocation flag.
    pub revoked: bool,
    /// Producer lifecycle deletion flag.
    pub deleted: bool,
    /// Whether reviewed source policy permits this record to contribute to enforcement.
    pub enforcement_eligible: bool,
    /// Optional tenant restriction; absence means source policy may treat the evidence as global.
    pub tenant_id: Option<String>,
    /// Optional producer data-marking identifier.
    pub marking: Option<String>,
    /// Licensing or terms reference required for evidence use and redistribution decisions.
    pub license_ref: String,
    /// Bounded provenance references that identify authenticated source material or derivation.
    pub provenance_refs: Vec<String>,
}

impl EvidenceRecordV1 {
    /// Validate contract shape and time ordering at an injected evaluation time.
    pub fn validate_at(&self, now_unix: u64) -> Result<(), ContractValidationErrorV1> {
        validate_schema(&self.schema_version)?;
        validate_text(&self.source_id, "source_id")?;
        validate_text(&self.producer_record_id, "producer_record_id")?;
        validate_text(&self.producer_record_version, "producer_record_version")?;
        self.subject.validate()?;
        validate_optional_text(self.producer_severity.as_deref(), "producer_severity")?;
        validate_optional_text(self.tenant_id.as_deref(), "tenant_id")?;
        validate_optional_text(self.marking.as_deref(), "marking")?;
        validate_text(&self.license_ref, "license_ref")?;
        validate_text_list(&self.provenance_refs, "provenance_refs")?;
        if self.enforcement_eligible && self.provenance_refs.is_empty() {
            return Err(ContractValidationErrorV1::MissingEnforcementProvenance);
        }
        if self.observed_at_unix > self.received_at_unix
            || self.received_at_unix > now_unix
            || self.valid_from_unix > self.valid_until_unix
        {
            return Err(ContractValidationErrorV1::InvalidTimeOrder);
        }
        if self
            .producer_confidence
            .is_some_and(|confidence| confidence > 100)
        {
            return Err(ContractValidationErrorV1::InvalidConfidence);
        }
        Ok(())
    }
}

/// Policy attached to one reviewed evidence source.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SourcePolicyV1 {
    /// Contract schema identifier.
    pub schema_version: String,
    /// Stable source identifier referenced by evidence and policy snapshots.
    pub source_id: String,
    /// Whether this source can establish known-malicious enforcement evidence.
    pub enforcement_capable: bool,
    /// Canonical subject kinds the source is permitted to assert.
    pub permitted_subject_kinds: Vec<DestinationSubjectKindV1>,
    /// Maximum evidence age allowed by Wardnet policy, in seconds.
    pub max_evidence_age_seconds: u64,
    /// Purposes for which this source may contribute; empty is invalid.
    pub allowed_purposes: Vec<String>,
}

impl SourcePolicyV1 {
    /// Validate source-policy shape without fetching or authenticating a source.
    pub fn validate(&self) -> Result<(), ContractValidationErrorV1> {
        validate_schema(&self.schema_version)?;
        validate_text(&self.source_id, "source_id")?;
        if self.permitted_subject_kinds.is_empty() || self.allowed_purposes.is_empty() {
            return Err(ContractValidationErrorV1::EmptySourceEligibility);
        }
        if self.permitted_subject_kinds.len() > MAX_LIST_ITEMS_V1 {
            return Err(ContractValidationErrorV1::BoundExceeded(
                "permitted_subject_kinds",
            ));
        }
        validate_text_list(&self.allowed_purposes, "allowed_purposes")?;
        Ok(())
    }
}

/// Runtime policy mode; monitor never manufactures a protect authorization.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EvaluationModeV1 {
    /// Enforce fail-closed reputation policy.
    Protect,
    /// Produce a shadow result without a protect grant.
    Monitor,
}

/// Immutable reputation policy revision consumed by the pure core.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicySnapshotV1 {
    /// Contract schema identifier.
    pub schema_version: String,
    /// Stable policy identifier.
    pub policy_id: String,
    /// Monotonic immutable policy revision.
    pub revision: u64,
    /// Evaluation mode.
    pub mode: EvaluationModeV1,
    /// Nonempty reviewed sources required for protect evaluation.
    pub required_sources: Vec<String>,
    /// Policy validity start.
    pub valid_from_unix: u64,
    /// Policy validity end.
    pub valid_until_unix: u64,
}

impl PolicySnapshotV1 {
    /// Validate the policy snapshot at an injected evaluation time.
    pub fn validate_at(&self, now_unix: u64) -> Result<(), ContractValidationErrorV1> {
        validate_schema(&self.schema_version)?;
        validate_text(&self.policy_id, "policy_id")?;
        if self.mode == EvaluationModeV1::Protect && self.required_sources.is_empty() {
            return Err(ContractValidationErrorV1::EmptyRequiredSources);
        }
        validate_text_list(&self.required_sources, "required_sources")?;
        for (index, source) in self.required_sources.iter().enumerate() {
            if self.required_sources[..index].contains(source) {
                return Err(ContractValidationErrorV1::DuplicateRequiredSource);
            }
        }
        if self.valid_from_unix > self.valid_until_unix
            || now_unix < self.valid_from_unix
            || now_unix > self.valid_until_unix
        {
            return Err(ContractValidationErrorV1::InvalidTimeOrder);
        }
        Ok(())
    }
}

/// Deterministic assessment dimension kept separate from policy action.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReputationAssessmentV1 {
    /// At least one active eligible reviewed source asserts known maliciousness.
    KnownMalicious,
    /// Adverse evidence exists but does not establish known maliciousness.
    Suspicious,
    /// No active eligible adverse match establishes safety.
    Unknown,
}

/// Health of the evidence authorities required by the evaluated policy.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceHealthV1 {
    /// All required authorities and applicable evidence are current.
    Fresh,
    /// Optional authority degradation exists while all required authorities remain healthy.
    Degraded,
    /// Required evidence exists but is outside its validity or age bound.
    Expired,
    /// A required authority or its verifiable evidence is unavailable.
    Unavailable,
}

/// Reputation policy action; transport authorization remains a separate authority.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PolicyActionV1 {
    /// Reputation policy allows continuation to other independent gates.
    Allow,
    /// Reputation policy denies continuation.
    Deny,
}

/// Stable machine-readable reason for a reputation policy action.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DecisionReasonV1 {
    /// An eligible hard-threat record matched the exact evaluated scope.
    KnownMalicious,
    /// Suspicious evidence caused the initial protect profile to deny.
    Suspicious,
    /// No adverse match exists, but the destination remains unknown without authorization.
    UnknownDestination,
    /// Required evidence or authority is unavailable or unverifiable.
    RequiredAuthorityUnavailable,
    /// Contract identity or version could not be validated.
    InvalidContract,
}

/// Explainable pure-core decision envelope; it is not proof that traffic was actually blocked.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DecisionEnvelopeV1 {
    /// Contract schema identifier.
    pub schema_version: String,
    /// Unique evaluation identifier.
    pub evaluation_id: String,
    /// Authenticated request and canonical destination identity evaluated by this decision.
    pub context: DestinationContextV1,
    /// Policy identifier used for the decision.
    pub policy_id: String,
    /// Exact policy revision used for the decision.
    pub policy_revision: u64,
    /// Immutable evidence snapshot generation evaluated by this decision.
    pub evidence_generation: String,
    /// Deterministic security assessment.
    pub assessment: ReputationAssessmentV1,
    /// Required evidence health.
    pub evidence_health: EvidenceHealthV1,
    /// Reputation-only policy action.
    pub action: PolicyActionV1,
    /// Stable explanation reason.
    pub reason: DecisionReasonV1,
    /// Evaluation time.
    pub evaluated_at_unix: u64,
    /// Earliest expiry across policy and evidence used by the decision.
    pub expires_at_unix: u64,
    /// Bounded producer evidence references used for explanation.
    pub evidence_refs: Vec<String>,
}

impl DecisionEnvelopeV1 {
    /// Validate a serialized decision envelope without treating it as an authenticated grant.
    pub fn validate(&self) -> Result<(), ContractValidationErrorV1> {
        validate_schema(&self.schema_version)?;
        validate_text(&self.evaluation_id, "evaluation_id")?;
        self.context.validate()?;
        validate_text(&self.policy_id, "policy_id")?;
        validate_text(&self.evidence_generation, "evidence_generation")?;
        validate_text_list(&self.evidence_refs, "evidence_refs")?;
        if self.evaluated_at_unix > self.expires_at_unix {
            return Err(ContractValidationErrorV1::InvalidTimeOrder);
        }
        Ok(())
    }
}

/// Typed fail-closed validation errors for versioned reputation contracts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContractValidationErrorV1 {
    /// Schema identifier is unsupported by this crate version.
    UnsupportedSchema,
    /// Direction is not outbound.
    WrongDirection,
    /// A required bounded text field is blank.
    BlankField(&'static str),
    /// A bounded text or list field exceeds the v1 contract limit.
    BoundExceeded(&'static str),
    /// A destination kind/scope combination is ambiguous or unsupported.
    AmbiguousSubjectScope,
    /// A time interval or observed/received ordering is invalid.
    InvalidTimeOrder,
    /// A required-source policy contains no required sources.
    EmptyRequiredSources,
    /// A required-source identifier appears more than once.
    DuplicateRequiredSource,
    /// A producer confidence value exceeds the preserved 0-100 range.
    InvalidConfidence,
    /// A source policy does not permit any subject kind or purpose.
    EmptySourceEligibility,
    /// Evidence eligible for enforcement has no provenance reference.
    MissingEnforcementProvenance,
}
