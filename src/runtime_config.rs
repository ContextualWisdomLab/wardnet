//! Bootstrap adapter for non-secret runtime configuration.
//!
//! Environment variables remain an outer delivery concern. The runtime crate
//! consumes one validated snapshot instead of scattering `std::env::var` reads
//! across application code. Secret values and their credentials-file locator
//! remain owned by the separate credential-bootstrap boundary.

use crate::{AppConfig, CRED_ADMIN_TOKEN, CredentialRegistry};
#[cfg(test)]
use std::path::Path;
use std::path::PathBuf;

/// Immutable bootstrap snapshot for non-secret Wardnet runtime settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeConfiguration {
    /// Socket address the gateway binds during process startup.
    pub bind_addr: String,
    /// Optional standalone state file used by the gateway process.
    pub state_path: Option<PathBuf>,
    /// DNSBL zone origin published by the gateway.
    pub dnsbl_origin: String,
    /// Maximum retained security-event count.
    pub event_limit: usize,
    /// Per-client request allowance for the local limiter; zero disables it.
    pub rate_limit: u32,
    /// Local limiter fixed-window duration in seconds.
    pub rate_limit_window: u64,
    /// Maximum accepted HTTP request body size in bytes.
    pub max_body_bytes: usize,
}

impl RuntimeConfiguration {
    /// Default loopback listener for standalone operation.
    pub const DEFAULT_BIND_ADDR: &'static str = "127.0.0.1:8080";
    /// Default local limiter allowance; zero keeps rate limiting disabled.
    pub const DEFAULT_RATE_LIMIT: u32 = 0;
    /// Default local limiter fixed-window duration in seconds.
    pub const DEFAULT_RATE_LIMIT_WINDOW: u64 = 60;
    /// Default maximum accepted request body size in bytes.
    pub const DEFAULT_MAX_BODY_BYTES: usize = 1_048_576;

    /// Load the process-edge runtime snapshot from environment bootstrap input.
    ///
    /// Environment variables are deliberately restricted to this delivery
    /// adapter. They are bootstrap transport, not an application/domain
    /// configuration authority; callers receive the validated snapshot below.
    /// Secret bootstrap, including `WAF_IDS_CREDENTIALS_PATH`, is deliberately
    /// excluded and remains solely owned by [`CredentialRegistry`].
    pub fn from_env() -> Result<Self, Box<dyn std::error::Error>> {
        Self::from_lookup(|name| std::env::var(name).ok())
    }

    fn from_lookup(
        mut lookup: impl FnMut(&str) -> Option<String>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let bind_addr = lookup("BIND_ADDR").unwrap_or_else(|| Self::DEFAULT_BIND_ADDR.to_string());
        let state_path = lookup("WAF_IDS_STATE_PATH").map(PathBuf::from);
        let dnsbl_origin =
            lookup("DNSBL_ORIGIN").unwrap_or_else(|| AppConfig::DEFAULT_DNSBL_ORIGIN.to_string());
        let event_limit_raw = lookup("EVENT_LIMIT");
        let rate_limit_raw = lookup("RATE_LIMIT");
        let rate_limit_window_raw = lookup("RATE_LIMIT_WINDOW");
        let max_body_bytes_raw = lookup("MAX_BODY_BYTES");

        Ok(Self {
            bind_addr,
            state_path,
            dnsbl_origin,
            event_limit: parse_event_limit(event_limit_raw.as_deref())?,
            rate_limit: parse_u32_env(
                "RATE_LIMIT",
                rate_limit_raw.as_deref(),
                Self::DEFAULT_RATE_LIMIT,
            )?,
            rate_limit_window: parse_u64_env(
                "RATE_LIMIT_WINDOW",
                rate_limit_window_raw.as_deref(),
                Self::DEFAULT_RATE_LIMIT_WINDOW,
            )?,
            max_body_bytes: parse_u64_env(
                "MAX_BODY_BYTES",
                max_body_bytes_raw.as_deref(),
                Self::DEFAULT_MAX_BODY_BYTES as u64,
            )? as usize,
        })
    }

    /// Derive the application configuration from this non-secret snapshot and
    /// the independently bootstrapped secret registry.
    pub fn app_config(&self, credentials: &CredentialRegistry) -> AppConfig {
        AppConfig {
            admin_token: credentials
                .get_credential(CRED_ADMIN_TOKEN)
                .map(str::to_owned),
            state_path: self.state_path.clone(),
            dnsbl_origin: self.dnsbl_origin.clone(),
            event_limit: self.event_limit,
        }
    }
}

/// Parse the `EVENT_LIMIT` value (already read from the environment as an
/// optional string). Absent falls back to [`AppConfig::DEFAULT_EVENT_LIMIT`]; a
/// non-integer or zero value is a hard configuration error.
pub fn parse_event_limit(raw: Option<&str>) -> Result<usize, Box<dyn std::error::Error>> {
    let value = match raw {
        Some(raw) => raw.parse::<usize>().map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("EVENT_LIMIT must be a positive integer, got {raw:?}: {error}"),
            )
        })?,
        None => AppConfig::DEFAULT_EVENT_LIMIT,
    };
    if value == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "EVENT_LIMIT must be greater than zero",
        )
        .into());
    }
    Ok(value)
}

/// Parse a `u32` environment value (already read as an optional string),
/// returning `default` when absent and a configuration error when malformed.
pub fn parse_u32_env(
    name: &str,
    raw: Option<&str>,
    default: u32,
) -> Result<u32, Box<dyn std::error::Error>> {
    match raw {
        Some(raw) => Ok(raw.parse::<u32>().map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("{name} must be a non-negative integer, got {raw:?}: {error}"),
            )
        })?),
        None => Ok(default),
    }
}

/// Parse a `u64` environment value (already read as an optional string),
/// returning `default` when absent and a configuration error when malformed.
pub fn parse_u64_env(
    name: &str,
    raw: Option<&str>,
    default: u64,
) -> Result<u64, Box<dyn std::error::Error>> {
    match raw {
        Some(raw) => Ok(raw.parse::<u64>().map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("{name} must be a positive integer, got {raw:?}: {error}"),
            )
        })?),
        None => Ok(default),
    }
}

#[cfg(test)]
fn direct_runtime_env_read_offenders(root: &Path) -> Vec<PathBuf> {
    fn visit(root: &Path, current: &Path, offenders: &mut Vec<PathBuf>) {
        for entry in std::fs::read_dir(current).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                visit(root, &path, offenders);
                continue;
            }
            if path.extension().and_then(|ext| ext.to_str()) != Some("rs") {
                continue;
            }
            let rel = path.strip_prefix(root).unwrap().to_path_buf();
            let source = std::fs::read_to_string(&path).unwrap();
            if (source.contains("std::env::var(") || source.contains("std::env::var_os("))
                && rel != Path::new("credentials.rs")
                && rel != Path::new("runtime_config.rs")
            {
                offenders.push(rel);
            }
        }
    }

    let mut offenders = Vec::new();
    visit(root, root, &mut offenders);
    offenders.sort();
    offenders
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CRED_ADMIN_TOKENS, CredentialRegistry};
    use std::collections::HashMap;

    fn runtime_from_pairs(
        pairs: &[(&str, &str)],
    ) -> Result<RuntimeConfiguration, Box<dyn std::error::Error>> {
        let values = pairs
            .iter()
            .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
            .collect::<HashMap<_, _>>();
        RuntimeConfiguration::from_lookup(|name| values.get(name).cloned())
    }

    #[test]
    fn runtime_configuration_defaults_when_bootstrap_input_is_unset() {
        let config = runtime_from_pairs(&[]).unwrap();
        assert_eq!(config.bind_addr, RuntimeConfiguration::DEFAULT_BIND_ADDR);
        assert_eq!(config.state_path, None);
        assert_eq!(config.dnsbl_origin, AppConfig::DEFAULT_DNSBL_ORIGIN);
        assert_eq!(config.event_limit, AppConfig::DEFAULT_EVENT_LIMIT);
        assert_eq!(config.rate_limit, RuntimeConfiguration::DEFAULT_RATE_LIMIT);
        assert_eq!(
            config.rate_limit_window,
            RuntimeConfiguration::DEFAULT_RATE_LIMIT_WINDOW
        );
        assert_eq!(
            config.max_body_bytes,
            RuntimeConfiguration::DEFAULT_MAX_BODY_BYTES
        );
    }

    #[test]
    fn runtime_configuration_reads_one_non_secret_bootstrap_snapshot() {
        let config = runtime_from_pairs(&[
            ("BIND_ADDR", "127.0.0.1:9090"),
            ("WAF_IDS_STATE_PATH", "/tmp/state.json"),
            ("DNSBL_ORIGIN", "wardnet.example."),
            ("EVENT_LIMIT", "25"),
            ("RATE_LIMIT", "5"),
            ("RATE_LIMIT_WINDOW", "30"),
            ("MAX_BODY_BYTES", "4096"),
        ])
        .unwrap();

        assert_eq!(config.bind_addr, "127.0.0.1:9090");
        assert_eq!(config.state_path, Some(PathBuf::from("/tmp/state.json")));
        assert_eq!(config.dnsbl_origin, "wardnet.example.");
        assert_eq!(config.event_limit, 25);
        assert_eq!(config.rate_limit, 5);
        assert_eq!(config.rate_limit_window, 30);
        assert_eq!(config.max_body_bytes, 4096);
    }

    #[test]
    fn runtime_configuration_never_reads_secret_bootstrap_locator() {
        let config = RuntimeConfiguration::from_lookup(|name| {
            assert_ne!(
                name, "WAF_IDS_CREDENTIALS_PATH",
                "credential-file selection belongs exclusively to CredentialRegistry bootstrap"
            );
            None
        })
        .unwrap();
        assert_eq!(config.bind_addr, RuntimeConfiguration::DEFAULT_BIND_ADDR);
    }

    #[test]
    fn runtime_configuration_rejects_malformed_bounds_without_mutating_process_env() {
        assert!(runtime_from_pairs(&[("EVENT_LIMIT", "0")]).is_err());
        assert!(runtime_from_pairs(&[("RATE_LIMIT_WINDOW", "abc")]).is_err());
    }

    #[test]
    fn runtime_configuration_builds_app_config_from_registry() {
        let runtime = RuntimeConfiguration {
            bind_addr: RuntimeConfiguration::DEFAULT_BIND_ADDR.to_string(),
            state_path: Some(PathBuf::from("state.json")),
            dnsbl_origin: "dnsbl.example".to_string(),
            event_limit: 42,
            rate_limit: 7,
            rate_limit_window: 90,
            max_body_bytes: 1024,
        };
        let credentials = CredentialRegistry::bootstrap_secrets(
            None,
            Some("secret".to_string()),
            Some("tok:ops".to_string()),
        )
        .unwrap();

        let app = runtime.app_config(&credentials);
        assert_eq!(app.admin_token.as_deref(), Some("secret"));
        assert_eq!(app.state_path, Some(PathBuf::from("state.json")));
        assert_eq!(app.dnsbl_origin, "dnsbl.example");
        assert_eq!(app.event_limit, 42);
        assert_eq!(
            credentials.get_credential(CRED_ADMIN_TOKENS),
            Some("tok:ops")
        );
    }

    #[test]
    fn runtime_env_reads_stay_in_bootstrap_adapters_recursively() {
        let src_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let offenders = direct_runtime_env_read_offenders(&src_dir);
        assert!(
            offenders.is_empty(),
            "direct runtime env reads escaped bootstrap adapters: {offenders:?}"
        );
    }

    #[test]
    fn nested_runtime_env_read_is_detected_by_architecture_fitness_gate() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let temp = std::env::temp_dir().join(format!(
            "wardnet-runtime-config-{}-{unique}",
            std::process::id()
        ));
        let nested = temp.join("gateway").join("delivery");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(
            nested.join("leak.rs"),
            "fn bypass() { let _ = std::env::var(\"BIND_ADDR\"); }",
        )
        .unwrap();

        assert_eq!(
            direct_runtime_env_read_offenders(&temp),
            vec![PathBuf::from("gateway/delivery/leak.rs")]
        );
        std::fs::remove_dir_all(&temp).unwrap();
    }
}
