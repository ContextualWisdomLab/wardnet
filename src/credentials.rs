//! Secret-bearing and fetch-sensitive configuration via a process-local
//! credential registry.
//!
//! Org guidance: runtime code must not treat raw environment variables as the
//! source of secrets. Environment (and optional credentials file) are bootstrap
//! transports that seed this registry; handlers and auth checks read through
//! [`CredentialRegistry::get_credential`].

use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    io::ErrorKind,
    path::{Path, PathBuf},
};

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
    /// Return the redacted provenance label exposed in health and evidence APIs.
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
    /// Create an empty registry for tests and bootstrap paths with no secrets.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Look up a credential by its well-known registry key.
    pub fn get_credential(&self, name: &str) -> Option<&str> {
        self.values.get(name).map(String::as_str)
    }

    /// Report where the registry's admin credentials came from.
    pub fn source(&self) -> CredentialSource {
        self.source
    }

    /// Return whether at least one administrator credential is present.
    pub fn has_admin_auth(&self) -> bool {
        self.get_credential(CRED_ADMIN_TOKEN)
            .is_some_and(|v| !v.is_empty())
            || self
                .get_credential(CRED_ADMIN_TOKENS)
                .is_some_and(|v| !v.trim().is_empty())
    }

    /// Bootstrap the registry from the process-edge delivery environment.
    pub fn bootstrap_from_env() -> Result<(Self, Option<PathBuf>), String> {
        let credentials_path = std::env::var("WAF_IDS_CREDENTIALS_PATH")
            .ok()
            .map(PathBuf::from);
        let registry = Self::bootstrap_secrets(
            credentials_path.as_deref(),
            std::env::var("ADMIN_TOKEN").ok(),
            std::env::var("ADMIN_TOKENS").ok(),
        )?;
        Ok((registry, credentials_path))
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

        if let Some(path) = credentials_path {
            match std::fs::read_to_string(path) {
                Ok(content) => {
                    let file_map: HashMap<String, serde_json::Value> =
                        serde_json::from_str(&content).map_err(|error| {
                            format!(
                                "credentials file {} is not valid JSON: {error}",
                                path.display()
                            )
                        })?;
                    for key in [CRED_ADMIN_TOKEN, CRED_ADMIN_TOKENS] {
                        if let Some(raw) = file_map.get(key) {
                            let text = json_value_as_nonempty_string(raw);
                            if let Some(text) = text {
                                values.insert(key.to_string(), text);
                                admin_from_file = true;
                            }
                        }
                    }
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
            && let Some(token) = env_admin_token.filter(|value| !value.is_empty())
        {
            values.insert(CRED_ADMIN_TOKEN.to_string(), token);
            admin_from_env = true;
        }
        if !values.contains_key(CRED_ADMIN_TOKENS)
            && let Some(tokens) = env_admin_tokens.filter(|value| !value.is_empty())
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

/// Convert one credential JSON value into a stored non-empty string.
fn json_value_as_nonempty_string(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(text) if !text.is_empty() => Some(text.clone()),
        serde_json::Value::Null | serde_json::Value::String(_) => None,
        other => {
            let text = other.to_string();
            if text.is_empty() || text == "null" {
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
}
