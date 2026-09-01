//! Bootstrap adapter for non-secret runtime configuration.
//!
//! Environment variables remain an outer delivery concern. The runtime crate
//! consumes one validated snapshot instead of scattering `std::env::var` reads
//! across application code.

use crate::{AppConfig, CRED_ADMIN_TOKEN, CredentialRegistry};
use std::path::PathBuf;

#[cfg(test)]
use std::sync::Mutex;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeConfiguration {
    pub bind_addr: String,
    pub credentials_path: Option<PathBuf>,
    pub state_path: Option<PathBuf>,
    pub dnsbl_origin: String,
    pub event_limit: usize,
    pub rate_limit: u32,
    pub rate_limit_window: u64,
    pub max_body_bytes: usize,
}

impl RuntimeConfiguration {
    pub const DEFAULT_BIND_ADDR: &'static str = "127.0.0.1:8080";
    pub const DEFAULT_RATE_LIMIT: u32 = 0;
    pub const DEFAULT_RATE_LIMIT_WINDOW: u64 = 60;
    pub const DEFAULT_MAX_BODY_BYTES: usize = 1_048_576;

    pub fn from_env() -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            bind_addr: std::env::var("BIND_ADDR")
                .unwrap_or_else(|_| Self::DEFAULT_BIND_ADDR.to_string()),
            credentials_path: std::env::var("WAF_IDS_CREDENTIALS_PATH")
                .ok()
                .map(PathBuf::from),
            state_path: std::env::var("WAF_IDS_STATE_PATH").ok().map(PathBuf::from),
            dnsbl_origin: std::env::var("DNSBL_ORIGIN")
                .unwrap_or_else(|_| AppConfig::DEFAULT_DNSBL_ORIGIN.to_string()),
            event_limit: parse_event_limit(std::env::var("EVENT_LIMIT").ok().as_deref())?,
            rate_limit: parse_u32_env(
                "RATE_LIMIT",
                std::env::var("RATE_LIMIT").ok().as_deref(),
                Self::DEFAULT_RATE_LIMIT,
            )?,
            rate_limit_window: parse_u64_env(
                "RATE_LIMIT_WINDOW",
                std::env::var("RATE_LIMIT_WINDOW").ok().as_deref(),
                Self::DEFAULT_RATE_LIMIT_WINDOW,
            )?,
            max_body_bytes: parse_u64_env(
                "MAX_BODY_BYTES",
                std::env::var("MAX_BODY_BYTES").ok().as_deref(),
                Self::DEFAULT_MAX_BODY_BYTES as u64,
            )? as usize,
        })
    }

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
mod tests {
    use super::*;
    use crate::{CRED_ADMIN_TOKENS, CredentialRegistry};

    static ENV_GUARD: Mutex<()> = Mutex::new(());

    fn clear_runtime_env() {
        for name in [
            "BIND_ADDR",
            "WAF_IDS_CREDENTIALS_PATH",
            "WAF_IDS_STATE_PATH",
            "DNSBL_ORIGIN",
            "EVENT_LIMIT",
            "RATE_LIMIT",
            "RATE_LIMIT_WINDOW",
            "MAX_BODY_BYTES",
            "ADMIN_TOKEN",
            "ADMIN_TOKENS",
        ] {
            unsafe { std::env::remove_var(name) };
        }
    }

    #[test]
    fn runtime_configuration_defaults_when_env_is_unset() {
        let _guard = ENV_GUARD.lock().unwrap();
        clear_runtime_env();

        let config = RuntimeConfiguration::from_env().unwrap();
        assert_eq!(config.bind_addr, RuntimeConfiguration::DEFAULT_BIND_ADDR);
        assert_eq!(config.credentials_path, None);
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
    fn runtime_configuration_reads_current_env_snapshot() {
        let _guard = ENV_GUARD.lock().unwrap();
        clear_runtime_env();
        unsafe {
            std::env::set_var("BIND_ADDR", "127.0.0.1:9090");
            std::env::set_var("WAF_IDS_CREDENTIALS_PATH", "/tmp/creds.json");
            std::env::set_var("WAF_IDS_STATE_PATH", "/tmp/state.json");
            std::env::set_var("DNSBL_ORIGIN", "wardnet.example.");
            std::env::set_var("EVENT_LIMIT", "25");
            std::env::set_var("RATE_LIMIT", "5");
            std::env::set_var("RATE_LIMIT_WINDOW", "30");
            std::env::set_var("MAX_BODY_BYTES", "4096");
        }

        let config = RuntimeConfiguration::from_env().unwrap();
        assert_eq!(config.bind_addr, "127.0.0.1:9090");
        assert_eq!(
            config.credentials_path,
            Some(PathBuf::from("/tmp/creds.json"))
        );
        assert_eq!(config.state_path, Some(PathBuf::from("/tmp/state.json")));
        assert_eq!(config.dnsbl_origin, "wardnet.example.");
        assert_eq!(config.event_limit, 25);
        assert_eq!(config.rate_limit, 5);
        assert_eq!(config.rate_limit_window, 30);
        assert_eq!(config.max_body_bytes, 4096);
    }

    #[test]
    fn runtime_configuration_rejects_malformed_bounds() {
        let _guard = ENV_GUARD.lock().unwrap();
        clear_runtime_env();
        unsafe { std::env::set_var("EVENT_LIMIT", "0") };
        assert!(RuntimeConfiguration::from_env().is_err());

        clear_runtime_env();
        unsafe { std::env::set_var("RATE_LIMIT_WINDOW", "abc") };
        assert!(RuntimeConfiguration::from_env().is_err());
    }

    #[test]
    fn runtime_configuration_builds_app_config_from_registry() {
        let runtime = RuntimeConfiguration {
            bind_addr: RuntimeConfiguration::DEFAULT_BIND_ADDR.to_string(),
            credentials_path: None,
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
    fn runtime_env_reads_stay_in_bootstrap_adapters() {
        let src_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut offenders = Vec::new();
        for entry in std::fs::read_dir(&src_dir).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("rs") {
                continue;
            }
            let rel = path
                .strip_prefix(env!("CARGO_MANIFEST_DIR"))
                .unwrap()
                .to_string_lossy()
                .into_owned();
            let source = std::fs::read_to_string(&path).unwrap();
            if (source.contains("std::env::var(") || source.contains("std::env::var_os("))
                && rel != "src/credentials.rs"
                && rel != "src/runtime_config.rs"
            {
                offenders.push(rel);
            }
        }
        assert!(
            offenders.is_empty(),
            "direct runtime env reads escaped bootstrap adapters: {offenders:?}"
        );
    }
}
