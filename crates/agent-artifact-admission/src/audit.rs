use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::policy::{
    auditable_identifier, canonical_registry_url, normalize_https_source_uri, valid_text_field,
};
use crate::{
    AdmissionDecision, AdmissionPolicy, ArtifactCoordinate, DecisionKind, InstallIntent,
    InstructionSourceKind, ReasonCode, is_sha256_hex, sha256_hex,
};

const MAX_AUDIT_LINE_BYTES: usize = 64 * 1024;

/// Minimized content-addressed artifact identity persisted in audit evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditArtifact {
    /// Package ecosystem, such as `npm` or `cargo`.
    pub ecosystem: String,
    /// Exact package name.
    pub name: String,
    /// Exact package version.
    pub version: String,
    /// Reviewed normalized registry URL.
    pub registry_url: String,
    /// Reviewed package owner or publisher label.
    pub owner: String,
    /// Exact artifact SHA-256 digest.
    pub sha256: String,
}

impl AuditArtifact {
    fn from_coordinate(artifact: &ArtifactCoordinate) -> Self {
        Self {
            ecosystem: auditable_identifier("ecosystem", &artifact.ecosystem, 64),
            name: auditable_identifier("artifact", &artifact.name, 512),
            version: auditable_identifier("version", &artifact.version, 256),
            registry_url: canonical_registry_url(&artifact.registry_url).unwrap_or_else(|| {
                format!(
                    "registry:sha256:{}",
                    sha256_hex(artifact.registry_url.as_bytes())
                )
            }),
            owner: auditable_identifier("owner", &artifact.owner, 512),
            sha256: if is_sha256_hex(&artifact.sha256) {
                artifact.sha256.clone()
            } else {
                sha256_hex(artifact.sha256.as_bytes())
            },
        }
    }
}

/// Durable, minimized evidence for one authenticated admission attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditRecord {
    /// Milliseconds since the Unix epoch when the record was constructed.
    pub timestamp_unix_ms: u128,
    /// Caller-supplied stable request identifier or a malformed-body surrogate.
    pub request_id: String,
    /// Identity of the requesting agent or broker when available.
    pub actor_id: String,
    /// Workspace or repository identifier when available.
    pub workspace_id: String,
    /// Structured operation, such as `install`.
    pub operation: String,
    /// Final fail-closed decision.
    pub decision: DecisionKind,
    /// Stable machine-readable decision reasons.
    pub reason_codes: Vec<ReasonCode>,
    /// Stable policy identifier.
    pub policy_id: String,
    /// Immutable policy revision identifier.
    pub policy_revision: String,
    /// Instruction-source kind without untrusted raw content.
    pub source_kind: Option<InstructionSourceKind>,
    /// Source URI after removing query and fragment data.
    pub normalized_source_uri: Option<String>,
    /// SHA-256 digest of remote source content when supplied and valid.
    pub source_content_sha256: Option<String>,
    /// SHA-256 digest of the structured command vector or malformed body.
    pub command_sha256: String,
    /// SHA-256 digest of a malformed authenticated request body when parsing failed.
    pub request_body_sha256: Option<String>,
    /// Reviewed dependency-manifest digest supplied with a parsed request.
    pub manifest_sha256: Option<String>,
    /// Content-addressed artifact coordinates with no command argument token.
    pub artifacts: Vec<AuditArtifact>,
}

/// Stable audit persistence error that never exposes paths or untrusted payload data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditError {
    /// Serialization produced a record beyond the fixed audit-line budget.
    RecordTooLarge,
    /// JSON serialization failed.
    Serialization,
    /// The append-only sink could not durably persist the record.
    StorageUnavailable,
    /// The sink's internal serialization lock was poisoned.
    LockUnavailable,
    /// The system clock cannot produce a Unix timestamp.
    ClockUnavailable,
}

impl fmt::Display for AuditError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::RecordTooLarge => "audit record exceeds the bounded line size",
            Self::Serialization => "audit record serialization failed",
            Self::StorageUnavailable => "audit storage is unavailable",
            Self::LockUnavailable => "audit writer lock is unavailable",
            Self::ClockUnavailable => "audit timestamp is unavailable",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for AuditError {}

/// Append-only audit persistence boundary used by HTTP admission before returning a decision.
pub trait AuditSink: Send + Sync {
    /// Append and durably persist one complete audit record.
    fn append(&self, record: &AuditRecord) -> Result<(), AuditError>;
}

/// Append-only NDJSON file sink with serialized, flush-and-sync writes.
pub struct FileAuditSink {
    path: PathBuf,
    writer_lock: Mutex<()>,
}

impl FileAuditSink {
    /// Create a file-backed sink. The file is opened lazily on each append.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            writer_lock: Mutex::new(()),
        }
    }

    fn open_append_only(&self) -> io::Result<File> {
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(Path::new(&self.path))
    }
}

impl AuditSink for FileAuditSink {
    fn append(&self, record: &AuditRecord) -> Result<(), AuditError> {
        let encoded = encode_record(record)?;
        let _guard = self
            .writer_lock
            .lock()
            .map_err(|_| AuditError::LockUnavailable)?;
        let mut file = self
            .open_append_only()
            .map_err(|_| AuditError::StorageUnavailable)?;
        file.write_all(&encoded)
            .and_then(|_| file.write_all(b"\n"))
            .and_then(|_| file.flush())
            .and_then(|_| file.sync_data())
            .map_err(|_| AuditError::StorageUnavailable)
    }
}

/// In-memory append-only sink for embedding and deterministic tests.
#[derive(Default)]
pub struct MemoryAuditSink {
    records: Mutex<Vec<AuditRecord>>,
}

impl MemoryAuditSink {
    /// Return a snapshot of records in durable append order.
    pub fn records(&self) -> Result<Vec<AuditRecord>, AuditError> {
        self.records
            .lock()
            .map(|records| records.clone())
            .map_err(|_| AuditError::LockUnavailable)
    }
}

impl AuditSink for MemoryAuditSink {
    fn append(&self, record: &AuditRecord) -> Result<(), AuditError> {
        let _ = encode_record(record)?;
        self.records
            .lock()
            .map_err(|_| AuditError::LockUnavailable)?
            .push(record.clone());
        Ok(())
    }
}

/// Build minimized audit evidence from a parsed admission request and its decision.
pub fn build_audit_record(
    intent: &InstallIntent,
    decision: &AdmissionDecision,
) -> Result<AuditRecord, AuditError> {
    Ok(AuditRecord {
        timestamp_unix_ms: unix_timestamp_ms()?,
        request_id: auditable_identifier("request", &intent.request_id, 256),
        actor_id: auditable_identifier("actor", &intent.actor_id, 512),
        workspace_id: auditable_identifier("workspace", &intent.workspace_id, 512),
        operation: if valid_text_field(&intent.operation, 32) {
            intent.operation.clone()
        } else {
            "invalid".to_string()
        },
        decision: decision.decision,
        reason_codes: decision.reason_codes.clone(),
        policy_id: auditable_identifier("policy", &decision.policy_id, 256),
        policy_revision: auditable_identifier("policy_revision", &decision.policy_revision, 256),
        source_kind: Some(intent.source.kind),
        normalized_source_uri: intent
            .source
            .uri
            .as_deref()
            .and_then(normalize_https_source_uri),
        source_content_sha256: intent
            .source
            .content_sha256
            .as_ref()
            .filter(|digest| is_sha256_hex(digest))
            .cloned(),
        command_sha256: decision.command_sha256.clone(),
        request_body_sha256: None,
        manifest_sha256: is_sha256_hex(&intent.manifest_sha256)
            .then(|| intent.manifest_sha256.clone()),
        artifacts: intent
            .artifacts
            .iter()
            .take(64)
            .map(AuditArtifact::from_coordinate)
            .collect(),
    })
}

/// Build minimized evidence for authenticated JSON that failed strict parsing.
pub fn build_malformed_audit_record(
    policy: &AdmissionPolicy,
    request_body_sha256: &str,
) -> Result<AuditRecord, AuditError> {
    let digest = if is_sha256_hex(request_body_sha256) {
        request_body_sha256.to_string()
    } else {
        sha256_hex(request_body_sha256.as_bytes())
    };
    Ok(AuditRecord {
        timestamp_unix_ms: unix_timestamp_ms()?,
        request_id: format!("malformed:{digest}"),
        actor_id: "unavailable".to_string(),
        workspace_id: "unavailable".to_string(),
        operation: "unavailable".to_string(),
        decision: DecisionKind::Block,
        reason_codes: vec![ReasonCode::MalformedRequest],
        policy_id: auditable_identifier("policy", &policy.policy_id, 256),
        policy_revision: auditable_identifier("policy_revision", &policy.policy_revision, 256),
        source_kind: None,
        normalized_source_uri: None,
        source_content_sha256: None,
        command_sha256: digest.clone(),
        request_body_sha256: Some(digest),
        manifest_sha256: None,
        artifacts: Vec::new(),
    })
}

fn encode_record(record: &AuditRecord) -> Result<Vec<u8>, AuditError> {
    let encoded = serde_json::to_vec(record).map_err(|_| AuditError::Serialization)?;
    if encoded.len() > MAX_AUDIT_LINE_BYTES {
        return Err(AuditError::RecordTooLarge);
    }
    Ok(encoded)
}

fn unix_timestamp_ms() -> Result<u128, AuditError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .map_err(|_| AuditError::ClockUnavailable)
}
