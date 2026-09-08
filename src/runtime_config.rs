//! Bootstrap adapter for non-secret runtime configuration.
//!
//! Environment variables remain an outer delivery concern. The runtime crate
//! consumes one validated snapshot instead of scattering `std::env::var` reads
//! across application code. Secret values and their credentials-file locator
//! remain owned by the separate credential-bootstrap boundary.

use crate::{AppConfig, CRED_ADMIN_TOKEN, CredentialRegistry};
#[cfg(test)]
use std::path::Path;
use std::path::{Path as StdPath, PathBuf};

/// Deployment intent used to select fail-closed state-authority invariants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeploymentMode {
    /// Local or single-node operation where memory/file state remains valid.
    Standalone,
    /// Commercial production operation, which requires PostgreSQL authority.
    Production,
}

/// Canonical state authority selected for the Wardnet process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateAuthority {
    /// Process-local volatile state; valid only for standalone operation.
    Memory,
    /// Atomic JSON-file state; valid only for standalone operation.
    File,
    /// Durable PostgreSQL authority required by production operation.
    Postgres,
}

/// Immutable bootstrap snapshot for non-secret Wardnet runtime settings.
///
/// As of September 2026, this public type no longer carries a
/// `credentials_path` field. External callers that previously built
/// `RuntimeConfiguration` struct literals with that field must now bootstrap
/// secret-file selection through [`CredentialRegistry::bootstrap_from_env`] or
/// [`CredentialRegistry::bootstrap_secrets`] and keep
/// `RuntimeConfiguration` limited to non-secret listener, DNSBL, retention, and
/// explicit state-authority settings.
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
    /// Explicit deployment intent; never inferred from listener topology.
    pub deployment_mode: DeploymentMode,
    /// Explicit or standalone-compatible canonical state authority.
    pub state_authority: StateAuthority,
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
    /// Standalone deployment marker for callers that construct a snapshot.
    pub const STANDALONE_MODE: DeploymentMode = DeploymentMode::Standalone;
    /// Production deployment marker for callers that construct a snapshot.
    pub const PRODUCTION_MODE: DeploymentMode = DeploymentMode::Production;
    /// In-memory state authority marker for standalone callers.
    pub const MEMORY_AUTHORITY: StateAuthority = StateAuthority::Memory;
    /// File state authority marker for standalone callers.
    pub const FILE_AUTHORITY: StateAuthority = StateAuthority::File;
    /// PostgreSQL state authority marker for production callers.
    pub const POSTGRES_AUTHORITY: StateAuthority = StateAuthority::Postgres;

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

    /// Build the same runtime snapshot from an injected lookup source.
    ///
    /// Tests use this seam to prove startup consumes one immutable bootstrap
    /// view without mutating or re-reading process environment state.
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
        let deployment_mode_raw = lookup("WARDNET_DEPLOYMENT_MODE");
        let state_authority_raw = lookup("WARDNET_STATE_AUTHORITY");
        let deployment_mode = parse_deployment_mode(deployment_mode_raw.as_deref())?;
        let state_authority = parse_state_authority(
            deployment_mode,
            state_authority_raw.as_deref(),
            state_path.as_deref(),
        )?;

        let config = Self {
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
            deployment_mode,
            state_authority,
        };
        config.validate_state_authority()?;
        config.ensure_state_backend_available()?;
        Ok(config)
    }

    /// Validate that deployment intent and selected state authority cannot
    /// silently downgrade production to process memory or a local JSON file.
    pub fn validate_state_authority(&self) -> Result<(), Box<dyn std::error::Error>> {
        if self.deployment_mode == DeploymentMode::Production
            && self.state_authority != StateAuthority::Postgres
        {
            return Err(invalid_configuration(
                "production deployment requires PostgreSQL state authority",
            ));
        }

        match self.state_authority {
            StateAuthority::File if self.state_path.is_none() => Err(invalid_configuration(
                "file state authority requires an explicit state path",
            )),
            StateAuthority::Memory | StateAuthority::Postgres if self.state_path.is_some() => {
                Err(invalid_configuration(
                    "WAF_IDS_STATE_PATH is only valid when file state authority is selected",
                ))
            }
            _ => Ok(()),
        }
    }

    /// Reject a declared authority whose storage adapter is not present yet.
    ///
    /// This keeps the #80 PostgreSQL migration testable without allowing a
    /// production `postgres` declaration to fall through to in-memory state.
    /// The later PostgreSQL repository slice removes this guard only when the
    /// durable adapter is actually wired into startup.
    pub fn ensure_state_backend_available(&self) -> Result<(), Box<dyn std::error::Error>> {
        if self.state_authority == StateAuthority::Postgres {
            return Err(invalid_configuration(
                "PostgreSQL state authority selected, but the durable PostgreSQL adapter is not available",
            ));
        }
        Ok(())
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

fn invalid_configuration(message: &str) -> Box<dyn std::error::Error> {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, message).into()
}

fn parse_deployment_mode(raw: Option<&str>) -> Result<DeploymentMode, Box<dyn std::error::Error>> {
    match raw {
        None | Some("standalone") => Ok(DeploymentMode::Standalone),
        Some("production") => Ok(DeploymentMode::Production),
        Some(value) => Err(invalid_configuration(&format!(
            "WARDNET_DEPLOYMENT_MODE must be standalone or production, got {value:?}"
        ))),
    }
}

fn parse_state_authority(
    deployment_mode: DeploymentMode,
    raw: Option<&str>,
    state_path: Option<&StdPath>,
) -> Result<StateAuthority, Box<dyn std::error::Error>> {
    match raw {
        Some("memory") => Ok(StateAuthority::Memory),
        Some("file") => Ok(StateAuthority::File),
        Some("postgres") => Ok(StateAuthority::Postgres),
        Some(value) => Err(invalid_configuration(&format!(
            "WARDNET_STATE_AUTHORITY must be memory, file, or postgres, got {value:?}"
        ))),
        None if deployment_mode == DeploymentMode::Production => Err(invalid_configuration(
            "WARDNET_STATE_AUTHORITY must be explicitly set to postgres in production",
        )),
        None if state_path.is_some() => Ok(StateAuthority::File),
        None => Ok(StateAuthority::Memory),
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

/// Parse a positive `u64` environment value (already read as an optional
/// string), returning `default` when absent and a configuration error when the
/// supplied value is malformed or zero.
pub fn parse_u64_env(
    name: &str,
    raw: Option<&str>,
    default: u64,
) -> Result<u64, Box<dyn std::error::Error>> {
    let value = match raw {
        Some(raw) => raw.parse::<u64>().map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("{name} must be a positive integer, got {raw:?}: {error}"),
            )
        })?,
        None => default,
    };
    if value == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{name} must be greater than zero"),
        )
        .into());
    }
    Ok(value)
}

#[cfg(test)]
/// Detect syntax that imports or directly calls the process-environment API.
///
/// Importing `std::env` outside the two bootstrap adapters is itself forbidden:
/// otherwise aliases can hide later `var`/`var_os` calls from a literal-call
/// scan. Whitespace is ignored so normal rustfmt layouts and grouped imports
/// cannot change the architecture result.
fn source_uses_runtime_env(source: &str) -> bool {
    let compact = source
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect::<String>();

    if compact.contains("std::env::var(")
        || compact.contains("std::env::var_os(")
        || compact.contains("usestd::env;")
        || compact.contains("usestd::envas")
        || compact.contains("usestd::env::")
    {
        return true;
    }

    let mut remaining = compact.as_str();
    const GROUP_PREFIX: &str = "usestd::{";
    while let Some(start) = remaining.find(GROUP_PREFIX) {
        let group = &remaining[start + GROUP_PREFIX.len()..];
        let Some(end) = group.find("};") else {
            break;
        };
        if group[..end].split(',').any(|entry| {
            let entry = entry.trim_matches(['{', '}']);
            entry == "env" || entry.starts_with("envas") || entry.starts_with("env::")
        }) {
            return true;
        }
        remaining = &group[end + 2..];
    }

    false
}

#[cfg(test)]
/// Walk the Rust source tree and return any file that performs direct runtime
/// environment reads outside the approved bootstrap adapters.
fn direct_runtime_env_read_offenders(root: &Path) -> Vec<PathBuf> {
    /// Recurse through nested source directories and collect violating files.
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
            if rel == Path::new("credentials.rs") || rel == Path::new("runtime_config.rs") {
                continue;
            }
            let source = std::fs::read_to_string(&path).unwrap();
            if source_uses_runtime_env(&source) {
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

    /// Build a deterministic runtime snapshot from in-memory bootstrap pairs.
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
    /// Defaults apply when no non-secret bootstrap values are provided.
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
        assert_eq!(config.deployment_mode, DeploymentMode::Standalone);
        assert_eq!(config.state_authority, StateAuthority::Memory);
    }

    #[test]
    /// Every non-secret bootstrap field is read from the injected snapshot.
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
        assert_eq!(config.deployment_mode, DeploymentMode::Standalone);
        assert_eq!(config.state_authority, StateAuthority::File);
    }

    #[test]
    /// Production state authority must be explicit, PostgreSQL-backed, and unavailable until wired.
    fn runtime_configuration_requires_explicit_postgres_in_production() {
        assert!(runtime_from_pairs(&[("WARDNET_DEPLOYMENT_MODE", "production")]).is_err());
        assert!(
            runtime_from_pairs(&[
                ("WARDNET_DEPLOYMENT_MODE", "production"),
                ("WARDNET_STATE_AUTHORITY", "file"),
                ("WAF_IDS_STATE_PATH", "state.json"),
            ])
            .is_err()
        );
        assert!(
            runtime_from_pairs(&[
                ("WARDNET_DEPLOYMENT_MODE", "production"),
                ("WARDNET_STATE_AUTHORITY", "postgres"),
            ])
            .is_err(),
            "production must fail closed until the PostgreSQL adapter is wired"
        );

        let config = RuntimeConfiguration {
            bind_addr: RuntimeConfiguration::DEFAULT_BIND_ADDR.to_string(),
            state_path: None,
            dnsbl_origin: AppConfig::DEFAULT_DNSBL_ORIGIN.to_string(),
            event_limit: AppConfig::DEFAULT_EVENT_LIMIT,
            rate_limit: RuntimeConfiguration::DEFAULT_RATE_LIMIT,
            rate_limit_window: RuntimeConfiguration::DEFAULT_RATE_LIMIT_WINDOW,
            max_body_bytes: RuntimeConfiguration::DEFAULT_MAX_BODY_BYTES,
            deployment_mode: DeploymentMode::Production,
            state_authority: StateAuthority::Postgres,
        };
        config.validate_state_authority().unwrap();
        assert!(config.ensure_state_backend_available().is_err());
    }

    #[test]
    /// Unknown authority names and ambiguous dormant file paths fail closed.
    fn runtime_configuration_rejects_invalid_or_ambiguous_state_authority() {
        assert!(
            runtime_from_pairs(&[("WARDNET_DEPLOYMENT_MODE", "cluster")]).is_err(),
            "unknown deployment intent must not fall back to standalone"
        );
        assert!(
            runtime_from_pairs(&[("WARDNET_STATE_AUTHORITY", "sqlite")]).is_err(),
            "unknown state authority must not fall back to memory"
        );
        assert!(
            runtime_from_pairs(&[
                ("WARDNET_STATE_AUTHORITY", "memory"),
                ("WAF_IDS_STATE_PATH", "state.json"),
            ])
            .is_err(),
            "a dormant file path beside memory authority is split authority"
        );
    }

    #[test]
    /// Runtime bootstrap must not request the secret credentials-path selector.
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
    /// Invalid numeric bounds fail closed before the listener binds.
    fn runtime_configuration_rejects_malformed_bounds_without_mutating_process_env() {
        assert!(runtime_from_pairs(&[("EVENT_LIMIT", "0")]).is_err());
        assert!(runtime_from_pairs(&[("RATE_LIMIT_WINDOW", "abc")]).is_err());
        assert!(runtime_from_pairs(&[("RATE_LIMIT_WINDOW", "0")]).is_err());
        assert!(runtime_from_pairs(&[("MAX_BODY_BYTES", "0")]).is_err());
    }

    #[test]
    /// AppConfig combines standalone file state with registry-backed secrets.
    fn runtime_configuration_builds_app_config_from_registry() {
        let runtime = RuntimeConfiguration {
            bind_addr: RuntimeConfiguration::DEFAULT_BIND_ADDR.to_string(),
            state_path: Some(PathBuf::from("state.json")),
            dnsbl_origin: "dnsbl.example".to_string(),
            event_limit: 42,
            rate_limit: 7,
            rate_limit_window: 90,
            max_body_bytes: 1024,
            deployment_mode: DeploymentMode::Standalone,
            state_authority: StateAuthority::File,
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
    /// The architecture fitness gate rejects direct env reads outside adapters.
    fn runtime_env_reads_stay_in_bootstrap_adapters_recursively() {
        let src_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let offenders = direct_runtime_env_read_offenders(&src_dir);
        assert!(
            offenders.is_empty(),
            "direct runtime env reads escaped bootstrap adapters: {offenders:?}"
        );
    }

    #[test]
    /// The detector rejects direct calls and both direct and grouped env imports.
    fn runtime_env_syntax_detector_covers_alias_forms() {
        assert!(source_uses_runtime_env(
            "fn bypass() { let _ = std::env::var_os(\"BIND_ADDR\"); }"
        ));
        assert!(source_uses_runtime_env(
            "use std::env as process_env; fn bypass() { let _ = process_env::var(\"BIND_ADDR\"); }"
        ));
        assert!(source_uses_runtime_env(
            "use std::{fmt, env as process_env}; fn bypass() { let _ = process_env::var(\"BIND_ADDR\"); }"
        ));
        assert!(!source_uses_runtime_env("use std::fmt; fn harmless() {}"));
    }

    #[test]
    /// Nested source files are scanned so deep env reads cannot evade the gate.
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

    #[test]
    /// Importing `std::env` must not bypass the direct runtime-env fitness gate.
    fn aliased_runtime_env_module_read_is_detected_by_architecture_fitness_gate() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let temp = std::env::temp_dir().join(format!(
            "wardnet-runtime-config-alias-{}-{unique}",
            std::process::id()
        ));
        let nested = temp.join("gateway").join("delivery");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(
            nested.join("aliased_leak.rs"),
            "use std::env; fn bypass() { let _ = env::var(\"BIND_ADDR\"); }",
        )
        .unwrap();

        assert_eq!(
            direct_runtime_env_read_offenders(&temp),
            vec![PathBuf::from("gateway/delivery/aliased_leak.rs")]
        );
        std::fs::remove_dir_all(&temp).unwrap();
    }
}
