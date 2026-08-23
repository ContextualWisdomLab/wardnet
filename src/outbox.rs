//! Transactional outbox and leased workers (issue #81).
//!
//! Domain mutations and outbox rows commit in one PostgreSQL transaction.
//! Workers claim with `FOR UPDATE SKIP LOCKED`, retry with bounded backoff,
//! and record receipts under a unique idempotency key. Stdout SIEM export is
//! at-least-once; the database receipt is the exactly-once business ack.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const EVENT_SECURITY_RECORDED: &str = "security_event.recorded";
pub const EVENT_SNAPSHOT_REPLACED: &str = "policy.snapshot_replaced";
pub const SCHEMA_VERSION: i32 = 1;
pub const MAX_ATTEMPTS: i32 = 8;
pub const LEASE_SECONDS: i64 = 30;
pub const CLAIM_BATCH: i64 = 16;
/// Cap for `GET /api/outbox` and processed-row retention (mirrors `EVENT_LIMIT`).
pub const LIST_LIMIT: i64 = 1_000;
pub const STATUS_PENDING: &str = "pending";
pub const STATUS_LEASED: &str = "leased";
pub const STATUS_PROCESSED: &str = "processed";
pub const STATUS_DEAD_LETTER: &str = "dead_letter";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OutboxMessage {
    pub message_id: String,
    pub tenant_id: String,
    pub aggregate_id: String,
    pub aggregate_version: i64,
    pub event_type: String,
    pub schema_version: i32,
    pub created_unix: i64,
    pub payload_json: String,
    pub payload_hash: String,
    pub idempotency_key: String,
    pub message_status: String,
    pub lease_owner: Option<String>,
    pub lease_expires_unix: Option<i64>,
    pub attempt_count: i32,
    pub first_attempt_unix: Option<i64>,
    pub last_attempt_unix: Option<i64>,
    pub next_available_unix: i64,
    pub terminal_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct OutboxHealth {
    /// `ready` when PostgreSQL outbox tables are the authority; `disabled` otherwise.
    pub status: String,
    pub pending: i64,
    pub leased: i64,
    pub dead_letter: i64,
    pub oldest_age_seconds: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DispatchError {
    /// Retryable worker failure (timeout, 429, connection reset).
    #[allow(dead_code)]
    Transient(String),
    /// Poisoned or unauthorized payload; dead-letter without further retries.
    Permanent(String),
}

impl DispatchError {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Transient(message) | Self::Permanent(message) => message,
        }
    }

    pub fn is_permanent(&self) -> bool {
        matches!(self, Self::Permanent(_))
    }
}

pub fn payload_hash(payload_json: &str) -> String {
    let digest = Sha256::digest(payload_json.as_bytes());
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub fn security_event_ids(tenant_id: &str, event_id: u64) -> (String, String) {
    let idempotency_key = format!("security_event:{tenant_id}:{event_id}");
    (idempotency_key.clone(), idempotency_key)
}

pub fn snapshot_ids(
    tenant_id: &str,
    event_sequence: u64,
    audit_sequence: u64,
    hash: &str,
) -> (String, String) {
    let idempotency_key =
        format!("policy.snapshot:{tenant_id}:{event_sequence}:{audit_sequence}:{hash}");
    (idempotency_key.clone(), idempotency_key)
}

/// Bounded exponential backoff with deterministic jitter from `message_id`.
pub fn next_available_unix(now_unix: i64, attempt_count: i32, message_id: &str) -> i64 {
    let capped = attempt_count.clamp(0, 8);
    let exp = 1_i64 << capped;
    let jitter = message_id.bytes().fold(0_u8, |acc, byte| acc ^ byte) as i64 % exp.max(1);
    now_unix.saturating_add(exp).saturating_add(jitter)
}

pub fn should_dead_letter(attempt_count: i32, error: &DispatchError) -> bool {
    error.is_permanent() || attempt_count >= MAX_ATTEMPTS
}

/// Default production dispatcher. Security events are exported as stdout JSON
/// (at-least-once). Snapshot replacements record a local ack only.
pub fn dispatch_stdout(message: &OutboxMessage) -> Result<String, DispatchError> {
    match message.event_type.as_str() {
        EVENT_SECURITY_RECORDED => {
            println!("{}", message.payload_json);
            Ok(format!("stdout-siem:{}", message.payload_hash))
        }
        EVENT_SNAPSHOT_REPLACED => Ok(format!("local-ack:{}", message.payload_hash)),
        other => Err(DispatchError::Permanent(format!(
            "unknown outbox event type {other}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_hash_is_stable_sha256() {
        assert_eq!(
            payload_hash("a"),
            "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"
        );
        assert_ne!(payload_hash("a"), payload_hash("b"));
    }

    #[test]
    fn backoff_is_monotonic_and_deterministic() {
        let first = next_available_unix(1_000, 0, "msg-a");
        let second = next_available_unix(1_000, 1, "msg-a");
        let again = next_available_unix(1_000, 1, "msg-a");
        assert!(second >= first);
        assert_eq!(second, again);
        assert!(next_available_unix(1_000, 8, "msg-a") > second);
    }

    #[test]
    fn dead_letter_on_permanent_or_exhausted_attempts() {
        let transient = DispatchError::Transient("timeout".into());
        let permanent = DispatchError::Permanent("malformed".into());
        assert!(!should_dead_letter(1, &transient));
        assert!(should_dead_letter(MAX_ATTEMPTS, &transient));
        assert!(should_dead_letter(1, &permanent));
    }

    #[test]
    fn stdout_dispatcher_rejects_unknown_types() {
        let message = OutboxMessage {
            message_id: "x".into(),
            tenant_id: "local-lab".into(),
            aggregate_id: "x".into(),
            aggregate_version: 1,
            event_type: "not.a.type".into(),
            schema_version: 1,
            created_unix: 1,
            payload_json: "{}".into(),
            payload_hash: payload_hash("{}"),
            idempotency_key: "x".into(),
            message_status: STATUS_LEASED.into(),
            lease_owner: None,
            lease_expires_unix: None,
            attempt_count: 1,
            first_attempt_unix: None,
            last_attempt_unix: None,
            next_available_unix: 1,
            terminal_reason: None,
        };
        assert!(dispatch_stdout(&message).is_err());
        let mut snapshot = message.clone();
        snapshot.event_type = EVENT_SNAPSHOT_REPLACED.into();
        assert!(
            dispatch_stdout(&snapshot)
                .unwrap()
                .starts_with("local-ack:")
        );
    }
}
