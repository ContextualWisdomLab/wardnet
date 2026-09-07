//! Versioned, transport-neutral outbound site-reputation domain contracts.
//!
//! Contract terminology, research/standards grounding, rejected alternatives, and the explicit
//! separation from executable transport authorization are recorded in
//! [TRACEABILITY.md](../TRACEABILITY.md).

use serde::{Deserialize, Serialize};

/// Wire schema identifier for the first Wardnet reputation contract family.
pub const REPUTATION_SCHEMA_V1: &str = "wardnet.reputation.v1";

const MAX_TEXT_BYTES_V1: usize = 1_024;
const MAX_OBSERVABLE_URL_BYTES_V1: usize = 8 * 1_024;
const MAX_LIST_ITEMS_V1: usize = 64;
const MAX_DECISION_EVIDENCE_REFS_V1: usize = 32;

/// Rejects contract schema identities outside the explicitly supported v1 family.
fn validate_schema(schema_version: &str) -> Result<(), ContractValidationErrorV1> {
    if schema_version == REPUTATION_SCHEMA_V1 {
        Ok(())
    } else {
        Err(ContractValidationErrorV1::UnsupportedSchema)
    }
}

/// Applies a nonblank byte-bound contract to one required text field.
fn validate_text_with_limit(
    value: &str,
    field: &'static str,
    max_bytes: usize,
) -> Result<(), ContractValidationErrorV1> {
    if value.trim().is_empty() {
        return Err(ContractValidationErrorV1::BlankField(field));
    }
    if value.len() > max_bytes {
        return Err(ContractValidationErrorV1::BoundExceeded(field));
    }
    Ok(())
}

/// Applies the shared nonblank and byte-bound contract to one required text field.
fn validate_text(value: &str, field: &'static str) -> Result<(), ContractValidationErrorV1> {
    validate_text_with_limit(value, field, MAX_TEXT_BYTES_V1)
}

/// Applies required-text validation only when an optional producer field is present.
fn validate_optional_text(
    value: Option<&str>,
    field: &'static str,
) -> Result<(), ContractValidationErrorV1> {
    if let Some(value) = value {
        validate_text(value, field)?;
    }
    Ok(())
}

/// Bounds a repeated text field before validating every element with the shared text contract.
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
#[serde(deny_unknown_fields)]
pub struct DestinationSubjectV1 {
    /// Subject kind defining how the opaque canonical value may be matched.
    pub kind: DestinationSubjectKindV1,
    /// Canonical value produced by the owning canonicalization boundary.
    pub value: String,
    /// Explicit matching scope; non-host kinds must remain exact.
    pub scope: DestinationScopeV1,
}

impl DestinationSubjectV1 {
    /// Rejects blank subjects and prevents subdomain scope from being attached to non-host kinds.
    fn validate(&self) -> Result<(), ContractValidationErrorV1> {
        let max_bytes = match self.kind {
            DestinationSubjectKindV1::ObservableUrl => MAX_OBSERVABLE_URL_BYTES_V1,
            DestinationSubjectKindV1::ExactHost | DestinationSubjectKindV1::ActualAddress => {
                MAX_TEXT_BYTES_V1
            }
        };
        validate_text_with_limit(&self.value, "subject.value", max_bytes)?;
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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

/// Completeness marker for one authenticated reputation source generation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SourceSnapshotV1 {
    /// Contract schema identifier.
    pub schema_version: String,
    /// Stable reviewed source identifier.
    pub source_id: String,
    /// Immutable source generation identifier represented by this completed snapshot.
    pub source_generation: String,
    /// Time Wardnet completed admission of this source generation.
    pub completed_at_unix: u64,
    /// Time after which this source generation is no longer current for policy evaluation.
    pub valid_until_unix: u64,
}

impl SourceSnapshotV1 {
    /// Validate source-generation identity and temporal ordering without inventing source health.
    pub fn validate_at(&self, now_unix: u64) -> Result<(), ContractValidationErrorV1> {
        validate_schema(&self.schema_version)?;
        validate_text(&self.source_id, "source_snapshot.source_id")?;
        validate_text(&self.source_generation, "source_snapshot.source_generation")?;
        if self.completed_at_unix > now_unix || self.completed_at_unix > self.valid_until_unix {
            return Err(ContractValidationErrorV1::InvalidTimeOrder);
        }
        Ok(())
    }
}

/// Immutable aggregate proving which source generations were completely admitted for evaluation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvidenceSnapshotV1 {
    /// Contract schema identifier.
    pub schema_version: String,
    /// Immutable Wardnet evidence generation identifier.
    pub evidence_generation: String,
    /// Completed source generations represented by this aggregate.
    pub source_snapshots: Vec<SourceSnapshotV1>,
    /// Bounded evidence records admitted from the represented sources.
    pub records: Vec<EvidenceRecordV1>,
}

impl EvidenceSnapshotV1 {
    /// Validate aggregate completeness, source membership, and replay-safe record identity.
    pub fn validate_at(&self, now_unix: u64) -> Result<(), ContractValidationErrorV1> {
        validate_schema(&self.schema_version)?;
        validate_text(&self.evidence_generation, "evidence_generation")?;
        if self.source_snapshots.len() > MAX_LIST_ITEMS_V1 {
            return Err(ContractValidationErrorV1::BoundExceeded("source_snapshots"));
        }
        if self.records.len() > MAX_LIST_ITEMS_V1 {
            return Err(ContractValidationErrorV1::BoundExceeded("records"));
        }

        for (index, source_snapshot) in self.source_snapshots.iter().enumerate() {
            source_snapshot.validate_at(now_unix)?;
            if self.source_snapshots[..index]
                .iter()
                .any(|prior| prior.source_id == source_snapshot.source_id)
            {
                return Err(ContractValidationErrorV1::DuplicateSourceSnapshot);
            }
        }

        for (index, record) in self.records.iter().enumerate() {
            record.validate_at(now_unix)?;
            if !self
                .source_snapshots
                .iter()
                .any(|snapshot| snapshot.source_id == record.source_id)
            {
                return Err(ContractValidationErrorV1::MissingSourceSnapshot);
            }
            if self.records[..index].iter().any(|prior| {
                prior.source_id == record.source_id
                    && prior.producer_record_id == record.producer_record_id
            }) {
                return Err(ContractValidationErrorV1::DuplicateEvidenceRecord);
            }
        }

        Ok(())
    }
}

/// Reviewed tenant-eligibility semantics for one reputation evidence source.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SourceTenantScopeV1 {
    /// The reviewed source may contribute for any authenticated tenant.
    AllAuthenticatedTenants,
    /// The reviewed source may contribute only for an explicit bounded tenant set.
    ExplicitTenantSet,
}

/// Policy attached to one reviewed evidence source.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
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
    /// Explicit reviewed tenant-scope mode; omission is invalid on the v1 wire.
    pub tenant_scope: SourceTenantScopeV1,
    /// Bounded tenant identifiers when `tenant_scope` is `explicit_tenant_set`.
    pub allowed_tenant_ids: Vec<String>,
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
        validate_text_list(&self.allowed_tenant_ids, "allowed_tenant_ids")?;
        match self.tenant_scope {
            SourceTenantScopeV1::AllAuthenticatedTenants if !self.allowed_tenant_ids.is_empty() => {
                return Err(ContractValidationErrorV1::InvalidTenantEligibility);
            }
            SourceTenantScopeV1::ExplicitTenantSet if self.allowed_tenant_ids.is_empty() => {
                return Err(ContractValidationErrorV1::InvalidTenantEligibility);
            }
            _ => {}
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
#[serde(deny_unknown_fields)]
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
    /// No active eligible adverse match exists, and no exact-scope authorization applies.
    UnknownDestination,
    /// An exact-scope business authorization permits an unknown destination to continue to other gates.
    BusinessAuthorization,
    /// Required evidence or authority is unavailable or unverifiable.
    RequiredAuthorityUnavailable,
    /// Contract identity or version could not be validated.
    InvalidContract,
}

/// Checks that the reason describes the assessment, with authority-health failure taking precedence.
fn reason_matches_assessment(
    assessment: ReputationAssessmentV1,
    evidence_health: EvidenceHealthV1,
    reason: DecisionReasonV1,
) -> bool {
    if matches!(
        evidence_health,
        EvidenceHealthV1::Expired | EvidenceHealthV1::Unavailable
    ) {
        return reason == DecisionReasonV1::RequiredAuthorityUnavailable;
    }

    match assessment {
        ReputationAssessmentV1::KnownMalicious => reason == DecisionReasonV1::KnownMalicious,
        ReputationAssessmentV1::Suspicious => reason == DecisionReasonV1::Suspicious,
        ReputationAssessmentV1::Unknown => matches!(
            reason,
            DecisionReasonV1::UnknownDestination
                | DecisionReasonV1::BusinessAuthorization
                | DecisionReasonV1::InvalidContract
        ),
    }
}

/// Checks whether a machine-readable reason is coherent with the reputation-only policy action.
fn reason_matches_action(action: PolicyActionV1, reason: DecisionReasonV1) -> bool {
    match action {
        PolicyActionV1::Allow => reason == DecisionReasonV1::BusinessAuthorization,
        PolicyActionV1::Deny => reason != DecisionReasonV1::BusinessAuthorization,
    }
}

/// Immutable, exact-scope Wardnet evidence for one reviewed business authorization.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BusinessAuthorizationBindingV1 {
    /// Contract schema identifier.
    pub schema_version: String,
    /// Immutable authorization identity.
    pub authorization_id: String,
    /// Monotonic immutable authorization revision; zero is invalid.
    pub authorization_revision: u64,
    /// Exact reputation policy identity reviewed for this authorization.
    pub policy_id: String,
    /// Exact immutable reputation policy revision reviewed for this authorization.
    pub policy_revision: u64,
    /// Authority that issued or approved the authorization.
    pub authority: String,
    /// Origin system or record family from which the authorization was admitted.
    pub origin: String,
    /// Exact authenticated tenant to which the authorization applies.
    pub tenant_id: String,
    /// Exact authenticated workload to which the authorization applies.
    pub workload_id: String,
    /// Exact registered purpose to which the authorization applies.
    pub purpose: String,
    /// Exact reputation profile to which the authorization applies.
    pub profile_id: String,
    /// Exact canonical destination subject to which the authorization applies.
    pub subject: DestinationSubjectV1,
    /// Exact external canonicalization profile under which the subject was reviewed.
    pub canonicalization_profile: String,
    /// Exact external canonicalization profile version under which the subject was reviewed.
    pub canonicalization_version: String,
    /// Inclusive authorization validity start.
    pub valid_from_unix: u64,
    /// Inclusive authorization validity end.
    pub valid_until_unix: u64,
    /// Revoked authorizations can never grant continuation.
    pub revoked: bool,
    /// Human or governed authority identity that approved the authorization.
    pub approver_id: String,
    /// Auditable ticket, case, or decision record reference.
    pub ticket_ref: String,
    /// Bounded immutable provenance references for authorization evidence.
    pub provenance_refs: Vec<String>,
}

impl BusinessAuthorizationBindingV1 {
    /// Validate the authorization shape and lifecycle at an injected evaluation time.
    pub fn validate_at(&self, now_unix: u64) -> Result<(), ContractValidationErrorV1> {
        validate_schema(&self.schema_version)?;
        validate_text(
            &self.authorization_id,
            "business_authorization.authorization_id",
        )?;
        if self.authorization_revision == 0 {
            return Err(ContractValidationErrorV1::InvalidBusinessAuthorizationRevision);
        }
        validate_text(&self.policy_id, "business_authorization.policy_id")?;
        validate_text(&self.authority, "business_authorization.authority")?;
        validate_text(&self.origin, "business_authorization.origin")?;
        validate_text(&self.tenant_id, "business_authorization.tenant_id")?;
        validate_text(&self.workload_id, "business_authorization.workload_id")?;
        validate_text(&self.purpose, "business_authorization.purpose")?;
        validate_text(&self.profile_id, "business_authorization.profile_id")?;
        self.subject.validate()?;
        if self.subject.scope != DestinationScopeV1::Exact {
            return Err(ContractValidationErrorV1::NonExactBusinessAuthorizationScope);
        }
        validate_text(
            &self.canonicalization_profile,
            "business_authorization.canonicalization_profile",
        )?;
        validate_text(
            &self.canonicalization_version,
            "business_authorization.canonicalization_version",
        )?;
        validate_text(&self.approver_id, "business_authorization.approver_id")?;
        validate_text(&self.ticket_ref, "business_authorization.ticket_ref")?;
        validate_text_list(
            &self.provenance_refs,
            "business_authorization.provenance_refs",
        )?;
        if self.provenance_refs.is_empty() {
            return Err(ContractValidationErrorV1::MissingBusinessAuthorizationProvenance);
        }
        if self.valid_from_unix > self.valid_until_unix {
            return Err(ContractValidationErrorV1::InvalidTimeOrder);
        }
        if self.revoked {
            return Err(ContractValidationErrorV1::RevokedBusinessAuthorization);
        }
        if now_unix < self.valid_from_unix || now_unix > self.valid_until_unix {
            return Err(ContractValidationErrorV1::ExpiredBusinessAuthorization);
        }
        Ok(())
    }

    /// Require exact business scope to match the already-authenticated evaluated context.
    fn matches_context(&self, context: &DestinationContextV1) -> bool {
        self.tenant_id == context.tenant_id
            && self.workload_id == context.workload_id
            && self.purpose == context.purpose
            && self.profile_id == context.profile_id
            && self.subject == context.subject
            && self.canonicalization_profile == context.canonicalization_profile
            && self.canonicalization_version == context.canonicalization_version
    }

    /// Require the authorization to have been reviewed for the exact immutable policy decision.
    fn matches_policy(&self, policy_id: &str, policy_revision: u64) -> bool {
        self.policy_id == policy_id && self.policy_revision == policy_revision
    }
}

/// Explainable pure-core decision envelope; it is not proof that traffic was actually blocked.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
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
    /// Policy mode bound to this decision; v1 decision envelopes are protect-only.
    pub policy_mode: EvaluationModeV1,
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
    /// Exact business-authorization evidence required only for the corresponding allow reason.
    pub business_authorization: Option<BusinessAuthorizationBindingV1>,
}

impl DecisionEnvelopeV1 {
    /// Validate a serialized decision envelope without treating it as an authenticated grant.
    pub fn validate(&self) -> Result<(), ContractValidationErrorV1> {
        validate_schema(&self.schema_version)?;
        validate_text(&self.evaluation_id, "evaluation_id")?;
        self.context.validate()?;
        validate_text(&self.policy_id, "policy_id")?;
        if self.policy_mode != EvaluationModeV1::Protect {
            return Err(ContractValidationErrorV1::WrongDecisionMode);
        }
        validate_text(&self.evidence_generation, "evidence_generation")?;
        if self.evidence_refs.len() > MAX_DECISION_EVIDENCE_REFS_V1 {
            return Err(ContractValidationErrorV1::BoundExceeded("evidence_refs"));
        }
        validate_text_list(&self.evidence_refs, "evidence_refs")?;
        if !reason_matches_assessment(self.assessment, self.evidence_health, self.reason) {
            return Err(ContractValidationErrorV1::InconsistentAssessmentReason);
        }
        let adverse_assessment = matches!(
            self.assessment,
            ReputationAssessmentV1::KnownMalicious | ReputationAssessmentV1::Suspicious
        );
        if adverse_assessment && self.evidence_refs.is_empty() {
            return Err(ContractValidationErrorV1::MissingDecisionEvidence);
        }
        if adverse_assessment && self.action == PolicyActionV1::Allow {
            return Err(ContractValidationErrorV1::UnsafeAdverseAllow);
        }
        let unhealthy_required_authority = matches!(
            self.evidence_health,
            EvidenceHealthV1::Expired | EvidenceHealthV1::Unavailable
        );
        if unhealthy_required_authority && self.action == PolicyActionV1::Allow {
            return Err(ContractValidationErrorV1::UnsafeUnhealthyEvidenceAllow);
        }
        if !reason_matches_action(self.action, self.reason) {
            return Err(ContractValidationErrorV1::InconsistentActionReason);
        }
        match (self.reason, self.business_authorization.as_ref()) {
            (DecisionReasonV1::BusinessAuthorization, Some(binding)) => {
                binding.validate_at(self.evaluated_at_unix)?;
                if !binding.matches_context(&self.context) {
                    return Err(ContractValidationErrorV1::BusinessAuthorizationContextMismatch);
                }
                if !binding.matches_policy(&self.policy_id, self.policy_revision) {
                    return Err(ContractValidationErrorV1::BusinessAuthorizationPolicyMismatch);
                }
                if self.expires_at_unix > binding.valid_until_unix {
                    return Err(ContractValidationErrorV1::BusinessAuthorizationExpiryMismatch);
                }
            }
            (DecisionReasonV1::BusinessAuthorization, None) => {
                return Err(ContractValidationErrorV1::MissingBusinessAuthorization);
            }
            (_, Some(_)) => {
                return Err(ContractValidationErrorV1::StrayBusinessAuthorization);
            }
            (_, None) => {}
        }
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
    /// A decision envelope is not bound to protect policy mode.
    WrongDecisionMode,
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
    /// A completed source identity appears more than once in one evidence snapshot.
    DuplicateSourceSnapshot,
    /// An evidence record has no completed source snapshot in the immutable aggregate.
    MissingSourceSnapshot,
    /// A producer record identity appears more than once in one evidence snapshot.
    DuplicateEvidenceRecord,
    /// A producer confidence value exceeds the preserved 0-100 range.
    InvalidConfidence,
    /// A source policy does not permit any subject kind or purpose.
    EmptySourceEligibility,
    /// A source policy tenant-scope mode contradicts its explicit tenant set.
    InvalidTenantEligibility,
    /// Evidence eligible for enforcement has no provenance reference.
    MissingEnforcementProvenance,
    /// An adverse decision assessment has no evidence reference for SOC traceability.
    MissingDecisionEvidence,
    /// Decision assessment and machine-readable reason contradict each other.
    InconsistentAssessmentReason,
    /// Decision action and machine-readable reason contradict each other.
    InconsistentActionReason,
    /// An adverse assessment attempts to serialize as an allow action.
    UnsafeAdverseAllow,
    /// Expired or unavailable required evidence attempts to serialize as an allow action.
    UnsafeUnhealthyEvidenceAllow,
    /// A business-authorization allow carries no bound authorization evidence.
    MissingBusinessAuthorization,
    /// Authorization evidence is attached to a decision that does not use it.
    StrayBusinessAuthorization,
    /// Authorization revision zero cannot identify an immutable reviewed revision.
    InvalidBusinessAuthorizationRevision,
    /// Business authorization widens beyond the exact destination subject scope.
    NonExactBusinessAuthorizationScope,
    /// Business authorization has no immutable provenance evidence.
    MissingBusinessAuthorizationProvenance,
    /// A revoked business authorization attempts to contribute to a decision.
    RevokedBusinessAuthorization,
    /// Business authorization is not valid at the decision evaluation time.
    ExpiredBusinessAuthorization,
    /// Business authorization scope differs from the authenticated evaluated context.
    BusinessAuthorizationContextMismatch,
    /// Business authorization was reviewed for a different policy identity or revision.
    BusinessAuthorizationPolicyMismatch,
    /// Decision lifetime extends beyond the bound business authorization lifetime.
    BusinessAuthorizationExpiryMismatch,
}
