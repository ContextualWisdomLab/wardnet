//! Secret-bearing and fetch-sensitive configuration via a process-local
//! credential registry.
//!
//! Org guidance: runtime code must not treat raw environment variables as the
//! source of secrets. Environment (and optional credentials file) are bootstrap
//! transports that seed this registry; handlers and auth checks read through
//! [`CredentialRegistry::get_credential`].

use serde::{Deserialize, Serialize};
use std::{collections::HashMap, io::ErrorKind, path::Path};

/// Well-known credentials loaded into the registry at bootstrap.
pub const CRED_ADMIN_TOKEN: &str = "admin_token";
pub const CRED_ADMIN_TOKENS: &str = "admin_tokens";

/// Where secret-bearing credentials were loaded from (never includes values).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum CredentialSource {
    /// At least one secret came from `WAF_IDS_CREDENTIALS_PATH`.
    File,
    /// Secrets came only from env bootstrap (`ADMIN_TOKEN` / `ADMIN_TOKENS`).
    Env,
    /// No admin secrets configured.
    #[default]
    None,
}

impl CredentialSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Env => "env",
            Self::None => "none",
        }
    }
}

/// In-process map of secret credentials. Values are never logged or serialized
/// into health/support surfaces — only the source label is exposed.
#[derive(Debug, Clone, Default)]
pub struct CredentialRegistry {
    values: HashMap<String, String>,
    source: CredentialSource,
}

impl CredentialRegistry {
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn get_credential(&self, name: &str) -> Option<&str> {
        self.values.get(name).map(String::as_str)
    }

    pub fn source(&self) -> CredentialSource {
        self.source
    }

    pub fn has_admin_auth(&self) -> bool {
        self.get_credential(CRED_ADMIN_TOKEN)
            .is_some_and(|v| !v.trim().is_empty())
            || self
                .get_credential(CRED_ADMIN_TOKENS)
                .is_some_and(|v| !v.trim().is_empty())
    }

    /// Bootstrap secret-bearing credentials plus the optional KEV fetch override.
    ///
    /// Precedence: JSON credentials file (when present) wins per-key; missing
    /// keys are filled from the env bootstrap values. Operational non-secret
    /// config (bind address, limits, DNSBL origin) stays on env. The KEV URL
    /// defaults to the built-in CISA endpoint and is accepted here only as a
    /// server-side override that must still satisfy the runtime allowlist.
    pub fn bootstrap_secrets(
        credentials_path: Option<&Path>,
        env_admin_token: Option<String>,
        env_admin_tokens: Option<String>,
    ) -> Result<Self, String> {
        let mut values = HashMap::new();
        // CredentialSource is documented (and reported via HealthStatus/support
        // bundle) as admin-secret provenance specifically.
        let mut admin_from_file = false;
        let mut admin_from_env = false;

        if let Some(path) = credentials_path.and_then(nonempty_credentials_path) {
            match std::fs::read_to_string(path) {
                Ok(content) => {
                    let file_values = parse_credentials_json(&content).map_err(|error| {
                        format!("credentials file {} is invalid: {error}", path.display())
                    })?;
                    if !file_values.is_empty() {
                        admin_from_file = true;
                    }
                    values.extend(file_values);
                }
                Err(error) if error.kind() == ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(format!(
                        "failed to read credentials file {}: {error}",
                        path.display()
                    ));
                }
            }
        }

        if !values.contains_key(CRED_ADMIN_TOKEN)
            && let Some(token) = env_admin_token.filter(|value| !value.trim().is_empty())
        {
            values.insert(CRED_ADMIN_TOKEN.to_string(), token);
            admin_from_env = true;
        }
        if !values.contains_key(CRED_ADMIN_TOKENS)
            && let Some(tokens) = env_admin_tokens.filter(|value| !value.trim().is_empty())
        {
            values.insert(CRED_ADMIN_TOKENS.to_string(), tokens);
            admin_from_env = true;
        }
        let source = if admin_from_file {
            CredentialSource::File
        } else if admin_from_env {
            CredentialSource::Env
        } else {
            CredentialSource::None
        };

        Ok(Self { values, source })
    }
}

/// Parse the secret-bearing keys from credentials JSON.
///
/// Missing keys may use bootstrap transport fallback, but an explicitly null
/// or blank key is invalid and cannot be silently replaced by another source.
pub fn parse_credentials_json(content: &str) -> Result<HashMap<String, String>, String> {
    let file_map: HashMap<String, serde_json::Value> =
        serde_json::from_str(content).map_err(|error| format!("not valid JSON: {error}"))?;
    let mut values = HashMap::new();
    for key in [CRED_ADMIN_TOKEN, CRED_ADMIN_TOKENS] {
        if let Some(raw) = file_map.get(key) {
            let text = json_value_as_nonempty_string(raw)
                .ok_or_else(|| format!("{key} must not be blank or null"))?;
            values.insert(key.to_string(), text);
        }
    }
    Ok(values)
}

/// Return a credentials path only when it contains a non-whitespace path value.
///
/// `WAF_IDS_CREDENTIALS_PATH` is an optional bootstrap transport. Treating an
/// empty environment value as a real path makes startup behavior depend on how
/// the host platform classifies `read_to_string("")`; normalizing it here keeps
/// the credential registry portable and fail-closed without inventing a file.
fn nonempty_credentials_path(path: &Path) -> Option<&Path> {
    if path.as_os_str().to_string_lossy().trim().is_empty() {
        None
    } else {
        Some(path)
    }
}

/// Constant-time equality for presented admin secrets.
///
/// Length inequality is mixed in as a boolean flag, not a truncated integer
/// XOR. Folding `(left.len() ^ right.len()) as u8` would treat lengths that
/// differ by a multiple of 256 as equal when the extra bytes are `0x00`.
pub fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let max = left.len().max(right.len());
    let mut diff = u8::from(left.len() != right.len());
    for i in 0..max {
        let l = left.get(i).copied().unwrap_or(0);
        let r = right.get(i).copied().unwrap_or(0);
        diff |= l ^ r;
    }
    diff == 0
}

/// True when `bind_addr` can only be reached from the local host.
///
/// Unparseable addresses return `false` (fail closed: require credentials).
pub fn listen_is_loopback_only(bind_addr: &str) -> bool {
    let trimmed = bind_addr.trim();
    if trimmed.is_empty() {
        return false;
    }
    if let Ok(addr) = trimmed.parse::<std::net::SocketAddr>() {
        return addr.ip().is_loopback();
    }
    let Some(host) = bind_host(trimmed) else {
        return false;
    };
    host.parse::<std::net::IpAddr>()
        .map(|ip| ip.is_loopback())
        .unwrap_or(false)
}

fn bind_host(bind_addr: &str) -> Option<&str> {
    if let Some(rest) = bind_addr.strip_prefix('[') {
        let end = rest.find(']')?;
        return Some(&rest[..end]);
    }
    bind_addr.rsplit_once(':').map(|(host, _)| host)
}

/// Fail closed before readiness when a non-loopback listener has no write-capable
/// admin principal. Loopback-only development remains available without a token.
///
/// This is the shipped gate behind [`crate::run_from_env`]; tests drive it
/// directly so the bind/listen path is not required to prove the policy.
pub fn require_write_auth_for_bind(
    bind_addr: &str,
    has_write_capable_admin: bool,
) -> Result<(), String> {
    if has_write_capable_admin || listen_is_loopback_only(bind_addr) {
        Ok(())
    } else {
        Err(format!(
            "refusing to bind {bind_addr} without a write-capable admin credential: set ADMIN_TOKEN, ADMIN_TOKENS, or WAF_IDS_CREDENTIALS_PATH before listening on a non-loopback address"
        ))
    }
}

fn json_value_as_nonempty_string(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(text) if !text.trim().is_empty() => Some(text.clone()),
        serde_json::Value::Null | serde_json::Value::String(_) => None,
        other => {
            let text = other.to_string();
            if text.trim().is_empty() || text == "null" {
                None
            } else {
                Some(text)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn bootstrap_from_env_only() {
        let registry = CredentialRegistry::bootstrap_secrets(
            None,
            Some("secret".to_string()),
            Some("tok:alice".to_string()),
        )
        .unwrap();
        assert_eq!(registry.source(), CredentialSource::Env);
        assert_eq!(registry.get_credential(CRED_ADMIN_TOKEN), Some("secret"));
        assert_eq!(
            registry.get_credential(CRED_ADMIN_TOKENS),
            Some("tok:alice")
        );
        assert!(registry.has_admin_auth());
    }

    #[test]
    fn bootstrap_empty_when_no_secrets() {
        let registry =
            CredentialRegistry::bootstrap_secrets(None, None, Some(String::new())).unwrap();
        assert_eq!(registry.source(), CredentialSource::None);
        assert!(!registry.has_admin_auth());
    }

    #[test]
    fn whitespace_env_admin_token_does_not_authorize_public_bind() {
        let registry =
            CredentialRegistry::bootstrap_secrets(None, Some("   \t".to_string()), None).unwrap();
        let has_write_capable_admin = registry
            .get_credential(CRED_ADMIN_TOKEN)
            .is_some_and(|token| !token.is_empty());
        assert_eq!(registry.source(), CredentialSource::None);
        assert_eq!(registry.get_credential(CRED_ADMIN_TOKEN), None);
        assert!(require_write_auth_for_bind("0.0.0.0:0", has_write_capable_admin).is_err());
    }

    #[test]
    fn whitespace_file_admin_token_cannot_fall_back_to_env() {
        let dir = std::env::temp_dir().join(format!(
            "wardnet-creds-whitespace-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("credentials.json");
        std::fs::write(&path, r#"{"admin_token":"   \t"}"#).unwrap();

        let error = CredentialRegistry::bootstrap_secrets(
            Some(&path),
            Some("must-not-replace-file-value".to_string()),
            None,
        )
        .unwrap_err();
        assert!(error.contains("admin_token must not be blank or null"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn explicit_null_file_admin_token_is_invalid() {
        assert!(parse_credentials_json(r#"{"admin_token":null}"#).is_err());
    }

    #[test]
    fn non_string_file_value_preserves_existing_serialization_policy() {
        let values = parse_credentials_json(r#"{"admin_token":42}"#).unwrap();
        assert_eq!(values.get(CRED_ADMIN_TOKEN).map(String::as_str), Some("42"));
    }

    #[test]
    fn file_overrides_env_per_key() {
        let dir = std::env::temp_dir().join(format!(
            "wardnet-creds-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("credentials.json");
        let mut file = std::fs::File::create(&path).unwrap();
        write!(
            file,
            r#"{{"admin_token":"from-file","admin_tokens":"filetok:operator"}}"#
        )
        .unwrap();
        drop(file);

        let registry = CredentialRegistry::bootstrap_secrets(
            Some(&path),
            Some("from-env".to_string()),
            Some("envtok:env".to_string()),
        )
        .unwrap();
        assert_eq!(registry.source(), CredentialSource::File);
        assert_eq!(registry.get_credential(CRED_ADMIN_TOKEN), Some("from-file"));
        assert_eq!(
            registry.get_credential(CRED_ADMIN_TOKENS),
            Some("filetok:operator")
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn file_partial_fills_missing_from_env() {
        let dir = std::env::temp_dir().join(format!(
            "wardnet-creds-partial-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("credentials.json");
        std::fs::write(&path, r#"{"admin_token":"file-only"}"#).unwrap();

        let registry = CredentialRegistry::bootstrap_secrets(
            Some(&path),
            Some("ignored".to_string()),
            Some("envtok:bob".to_string()),
        )
        .unwrap();
        assert_eq!(registry.source(), CredentialSource::File);
        assert_eq!(registry.get_credential(CRED_ADMIN_TOKEN), Some("file-only"));
        assert_eq!(
            registry.get_credential(CRED_ADMIN_TOKENS),
            Some("envtok:bob")
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_credentials_file_falls_back_to_env() {
        let path = std::env::temp_dir().join(format!(
            "wardnet-creds-missing-{}-{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let registry = CredentialRegistry::bootstrap_secrets(
            Some(&path),
            Some("env-secret".to_string()),
            None,
        )
        .unwrap();
        assert_eq!(registry.source(), CredentialSource::Env);
        assert_eq!(
            registry.get_credential(CRED_ADMIN_TOKEN),
            Some("env-secret")
        );
    }

    #[test]
    fn invalid_credentials_json_is_error() {
        let dir = std::env::temp_dir().join(format!(
            "wardnet-creds-bad-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("credentials.json");
        std::fs::write(&path, "not-json").unwrap();
        let err = CredentialRegistry::bootstrap_secrets(Some(&path), None, None).unwrap_err();
        assert!(err.contains("not valid JSON"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn constant_time_eq_matches_equal_secrets_and_rejects_others() {
        assert!(constant_time_eq(b"secret", b"secret"));
        assert!(!constant_time_eq(b"secret", b"secreT"));
        assert!(!constant_time_eq(b"secret", b"secret!"));
        assert!(!constant_time_eq(b"secret", b""));
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn constant_time_eq_rejects_lengths_differing_by_256_with_zero_suffix() {
        let short = vec![0_u8; 1];
        let long = vec![0_u8; 257];
        assert!(!constant_time_eq(&short, &long));
    }

    #[test]
    fn nonempty_credentials_path_filters_blank_values() {
        assert!(nonempty_credentials_path(Path::new("")).is_none());
        assert!(nonempty_credentials_path(Path::new("   ")).is_none());
        let path = Path::new("credentials.json");
        assert_eq!(nonempty_credentials_path(path), Some(path));
    }

    #[test]
    fn listen_is_loopback_only_classifies_bind_addresses() {
        assert!(listen_is_loopback_only("127.0.0.1:0"));
        assert!(listen_is_loopback_only("127.0.0.1:8080"));
        assert!(listen_is_loopback_only("[::1]:8080"));
        assert!(!listen_is_loopback_only("localhost:8080"));
        assert!(!listen_is_loopback_only("LOCALHOST:9"));
        assert!(!listen_is_loopback_only("0.0.0.0:0"));
        assert!(!listen_is_loopback_only("0.0.0.0:8080"));
        assert!(!listen_is_loopback_only("[::]:8080"));
        assert!(!listen_is_loopback_only("192.0.2.10:8080"));
        assert!(!listen_is_loopback_only(""));
        assert!(!listen_is_loopback_only("not-an-address"));
    }

    #[test]
    fn require_write_auth_for_bind_fail_closes_public_listeners() {
        require_write_auth_for_bind("127.0.0.1:0", false).unwrap();
        require_write_auth_for_bind("0.0.0.0:0", true).unwrap();
        let err = require_write_auth_for_bind("0.0.0.0:0", false).unwrap_err();
        assert!(
            err.contains("refusing to bind 0.0.0.0:0"),
            "operator error must name the refused address: {err}"
        );
        assert!(err.contains("ADMIN_TOKEN"), "{err}");
        let err = require_write_auth_for_bind("[::]:8080", false).unwrap_err();
        assert!(err.contains("refusing to bind [::]:8080"), "{err}");
    }
}
