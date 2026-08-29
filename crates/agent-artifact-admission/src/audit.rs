use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::{
    AdmissionDecision, ArtifactCoordinate, DecisionKind, InstallIntent, InstructionSourceKind,
    ReasonCode,
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

impl From<&ArtifactCoordinate> for AuditArtifact {
    fn from(artifact: &ArtifactCoordinate) -> Self {
        Self {
            ecosystem: artifact.ecosystem.clone(),
            name: artifact.name.clone(),
            version: artifact.version.clone(),
            registry_url: artifact.registry_url.clone(),
            owner: artifact.owner.clone(),
            sha256: artifact.sha256.clone(),
        }
    }
}

/// Durable, minimized evidence for one authenticated admission attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditRecord {
    /// Milliseconds since the Unix epoch when the record was constructed.
    pub timestamp_unix_ms: u128,
    /// Caller-supplied stable request identifier.
    pub request_id: String,
    /// Identity of the requesting agent or broker.
    pub actor_id: String,
    /// Workspace or repository identifier.
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
    pub source_kind: InstructionSourceKind,
    /// Source URI after removing query and fragment data.
    pub normalized_source_uri: Option<String>,
    /// SHA-256 digest of remote source content when supplied.
    pub source_content_sha256: Option<String>,
    /// SHA-256 digest of the structured command vector; raw argv is never persisted.
    pub command_sha256: String,
    /// Reviewed dependency-manifest digest supplied with the request.
    pub manifest_sha256: String,
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

/// Build minimized audit evidence from an admission request and its deterministic decision.
pub fn build_audit_record(intent: &InstallIntent, decision: &AdmissionDecision) -> AuditRecord {
    AuditRecord {
        timestamp_unix_ms: unix_timestamp_ms().unwrap_or_default(),
        request_id: intent.request_id.clone(),
        actor_id: intent.actor_id.clone(),
        workspace_id: intent.workspace_id.clone(),
        operation: intent.operation.clone(),
        decision: decision.decision,
        reason_codes: decision.reason_codes.clone(),
        policy_id: decision.policy_id.clone(),
        policy_revision: decision.policy_revision.clone(),
        source_kind: intent.source.kind,
        normalized_source_uri: decision.normalized_source_uri.clone(),
        source_content_sha256: intent.source.content_sha256.clone(),
        command_sha256: decision.command_sha256.clone(),
        manifest_sha256: intent.manifest_sha256.clone(),
        artifacts: intent.artifacts.iter().map(AuditArtifact::from).collect(),
    }
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
