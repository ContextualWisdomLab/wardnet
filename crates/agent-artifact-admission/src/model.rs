use serde::{Deserialize, Serialize};

/// Immutable admission policy loaded through reviewed configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct AdmissionPolicy {
    /// Stable policy identifier surfaced in responses and audit records.
    pub policy_id: String,
    /// Immutable policy revision identifier.
    pub policy_revision: String,
    /// Executables that may be considered for admission.
    #[serde(default)]
    pub allowed_executables: Vec<String>,
    /// Reviewed workspace manifest digests.
    #[serde(default)]
    pub approved_manifests: Vec<ApprovedManifest>,
    /// Exact approved install artifacts.
    #[serde(default)]
    pub approved_artifacts: Vec<ApprovedArtifact>,
}

impl AdmissionPolicy {
    /// Test helper that proves the evaluator blocks when nothing is approved.
    pub fn deny_all_for_test() -> Self {
        Self {
            policy_id: "deny-all".to_string(),
            policy_revision: "test".to_string(),
            allowed_executables: Vec::new(),
            approved_manifests: Vec::new(),
            approved_artifacts: Vec::new(),
        }
    }
}

/// Reviewed manifest identity allowed by policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovedManifest {
    /// Workspace identifier the reviewed manifest belongs to.
    pub workspace_id: String,
    /// Exact SHA-256 digest of the reviewed manifest.
    pub sha256: String,
}

/// Exact package artifact allowed by policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovedArtifact {
    /// Package ecosystem, such as `npm` or `cargo`.
    pub ecosystem: String,
    /// Exact package name.
    pub name: String,
    /// Exact package version.
    pub version: String,
    /// Normalized registry URL.
    pub registry_url: String,
    /// Reviewed package owner or publisher label.
    pub owner: String,
    /// Exact artifact SHA-256 digest.
    pub sha256: String,
    /// Exact argv token that names the artifact to install.
    pub artifact_argument: String,
}

/// One requested artifact inside an install intent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactCoordinate {
    /// Package ecosystem, such as `npm` or `cargo`.
    pub ecosystem: String,
    /// Exact package name.
    pub name: String,
    /// Exact package version.
    pub version: String,
    /// Normalized registry URL.
    pub registry_url: String,
    /// Claimed package owner or publisher label.
    pub owner: String,
    /// Exact artifact SHA-256 digest.
    pub sha256: String,
    /// Exact argv token that names the artifact to install.
    pub artifact_argument: String,
}

/// Provenance of the instruction that requested the install.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstructionSource {
    /// Untrusted source category.
    pub kind: InstructionSourceKind,
    /// Canonical source URI when available.
    pub uri: Option<String>,
    /// SHA-256 digest of the retrieved source content.
    pub content_sha256: Option<String>,
}

/// Untrusted instruction source kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstructionSourceKind {
    /// `llms.txt` retrieved from a remote origin.
    LlmsTxt,
    /// `llms-full.txt` retrieved from a remote origin.
    LlmsFullTxt,
    /// Arbitrary web page content.
    WebPage,
    /// Issue or PR comment content.
    IssueComment,
    /// Local reviewed manifest or operator-entered content.
    ReviewedConfig,
}

/// Structured install request evaluated before any executor runs it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallIntent {
    /// Stable request identifier supplied by the caller.
    pub request_id: String,
    /// Identity of the requesting agent or broker.
    pub actor_id: String,
    /// Workspace or repository identifier.
    pub workspace_id: String,
    /// Structured operation, limited to install in this slice.
    pub operation: String,
    /// Tokenized command vector; shell strings are forbidden upstream.
    pub argv: Vec<String>,
    /// Exact reviewed dependency-manifest digest for the workspace.
    pub manifest_sha256: String,
    /// Instruction provenance.
    pub source: InstructionSource,
    /// Exact install artifacts represented in `argv`.
    pub artifacts: Vec<ArtifactCoordinate>,
}

impl InstallIntent {
    /// Test helper representing an untrusted `llms.txt` package suggestion.
    pub fn unowned_llms_package_for_test() -> Self {
        Self {
            request_id: "req-test-0001".to_string(),
            actor_id: "agent:codex:test".to_string(),
            workspace_id: "ContextualWisdomLab/wardnet".to_string(),
            operation: "install".to_string(),
            argv: vec![
                "npm".to_string(),
                "install".to_string(),
                "@unowned/example@1.2.3".to_string(),
                "--ignore-scripts".to_string(),
            ],
            manifest_sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_string(),
            source: InstructionSource {
                kind: InstructionSourceKind::LlmsTxt,
                uri: Some("https://example.invalid/llms.txt".to_string()),
                content_sha256: Some(
                    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                        .to_string(),
                ),
            },
            artifacts: vec![ArtifactCoordinate {
                ecosystem: "npm".to_string(),
                name: "@unowned/example".to_string(),
                version: "1.2.3".to_string(),
                registry_url: "https://registry.npmjs.org".to_string(),
                owner: "Unowned".to_string(),
                sha256: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                    .to_string(),
                artifact_argument: "@unowned/example@1.2.3".to_string(),
            }],
        }
    }
}

/// Deterministic allow/block result returned to the caller.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionDecision {
    /// Original caller request identifier or a content-addressed malformed surrogate.
    pub request_id: String,
    /// Final policy decision.
    pub decision: DecisionKind,
    /// Stable machine-readable block reasons.
    pub reason_codes: Vec<ReasonCode>,
    /// Stable policy identifier.
    pub policy_id: String,
    /// Stable policy revision.
    pub policy_revision: String,
    /// Normalized source URI when present.
    pub normalized_source_uri: Option<String>,
    /// SHA-256 of the structured command vector or malformed request body.
    pub command_sha256: String,
    /// Number of artifacts the caller asked to install.
    pub artifact_count: usize,
}

/// Admission outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionKind {
    /// The command exactly matches policy.
    Allow,
    /// The command must not be executed.
    Block,
}

impl DecisionKind {
    /// Stable string form used by tests and callers that do not deserialize.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Block => "block",
        }
    }
}

/// Stable machine-readable block reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReasonCode {
    /// The request body could not be parsed as the strict install-intent schema.
    MalformedRequest,
    /// A bounded identifier, argument vector, source field, or count was invalid.
    InvalidRequest,
    /// The structured operation was not the supported install operation.
    InvalidOperation,
    /// The reviewed workspace manifest digest was malformed.
    InvalidManifestDigest,
    /// One or more artifact coordinates were malformed or unpinned.
    InvalidArtifact,
    /// Duplicate artifact identities or artifact argument tokens were supplied.
    DuplicateArtifact,
    /// No exact approved artifact matched the requested install.
    ArtifactNotApproved,
    /// No reviewed manifest matched the workspace digest.
    ManifestNotApproved,
    /// The executable is not on the explicit allowlist.
    ExecutableNotAllowed,
    /// The request omitted an executable.
    MissingExecutable,
    /// The request omitted a required remote source URI.
    MissingSourceUri,
    /// The request omitted a required source content digest.
    MissingSourceDigest,
    /// The request used an insecure or malformed source URI.
    InvalidSourceUri,
    /// The command path is forbidden even if otherwise allowlisted.
    ForbiddenCommand,
    /// The command attempted to introduce an alternate package trust root.
    AlternateTrustRoot,
    /// The package manager invocation omitted a mandatory hardening flag.
    MissingSafetyFlag,
    /// Durable audit evidence could not be persisted before returning a decision.
    AuditUnavailable,
}

impl ReasonCode {
    /// Stable string form used by tests and audit sinks.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MalformedRequest => "malformed_request",
            Self::InvalidRequest => "invalid_request",
            Self::InvalidOperation => "invalid_operation",
            Self::InvalidManifestDigest => "invalid_manifest_digest",
            Self::InvalidArtifact => "invalid_artifact",
            Self::DuplicateArtifact => "duplicate_artifact",
            Self::ArtifactNotApproved => "artifact_not_approved",
            Self::ManifestNotApproved => "manifest_not_approved",
            Self::ExecutableNotAllowed => "executable_not_allowed",
            Self::MissingExecutable => "missing_executable",
            Self::MissingSourceUri => "missing_source_uri",
            Self::MissingSourceDigest => "missing_source_digest",
            Self::InvalidSourceUri => "invalid_source_uri",
            Self::ForbiddenCommand => "forbidden_command",
            Self::AlternateTrustRoot => "alternate_trust_root",
            Self::MissingSafetyFlag => "missing_safety_flag",
            Self::AuditUnavailable => "audit_unavailable",
        }
    }
}
