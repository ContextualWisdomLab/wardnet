use std::collections::BTreeSet;
use std::fmt;
use std::fs::File;
use std::io::{self, Read};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use url::Url;

use crate::{AdmissionPolicy, is_sha256_hex};

const MAX_CONFIG_FILE_BYTES: u64 = 1024 * 1024;
const MAX_CREDENTIAL_FILE_BYTES: u64 = 16 * 1024;
const MAX_REQUEST_BODY_BYTES: usize = 1024 * 1024;
const MAX_ADMIN_TOKEN_BYTES: usize = 4096;
const MIN_ADMIN_TOKEN_BYTES: usize = 32;

/// Immutable process configuration for the agent-artifact admission service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionServiceConfig {
    /// Configuration schema version. Version `1` is the only supported revision.
    pub configuration_version: String,
    /// TCP listener address. The service accepts loopback addresses only.
    pub bind_address: String,
    /// Maximum accepted request body size in bytes.
    pub max_request_body_bytes: usize,
    /// Append-only NDJSON audit destination.
    pub audit_log_path: String,
    /// Reviewed admission policy applied to every install request.
    pub policy: AdmissionPolicy,
}

/// Strict credentials document loaded from a protected file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialFile {
    /// Bearer token required by the admission endpoint.
    pub admin_token: String,
}

/// Strict command-line arguments accepted by the standalone service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CliArgs {
    /// Path to the reviewed service configuration document.
    pub config_path: String,
    /// Path to the protected credentials document.
    pub credentials_path: String,
}

/// Stable configuration failure that does not expose file content or secret material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigError {
    /// Command-line arguments are missing, duplicated, or unknown.
    InvalidArguments,
    /// A configuration or credentials file could not be read.
    Io,
    /// A bounded file exceeded its fixed byte budget.
    FileTooLarge,
    /// JSON was malformed or contained unknown fields.
    InvalidJson,
    /// Service configuration violated a fail-closed invariant.
    InvalidConfiguration,
    /// Credential material violated the token contract.
    InvalidCredential,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidArguments => "invalid admission service arguments",
            Self::Io => "admission configuration is unavailable",
            Self::FileTooLarge => "admission configuration exceeds its size limit",
            Self::InvalidJson => "admission configuration JSON is invalid",
            Self::InvalidConfiguration => "admission service configuration is unsafe",
            Self::InvalidCredential => "admission credential is invalid",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for ConfigError {}

/// Parse the only supported CLI shape: one `--config` path and one `--credentials` path.
pub fn parse_cli_args(args: &[String]) -> Result<CliArgs, ConfigError> {
    let mut config_path = None;
    let mut credentials_path = None;
    let mut index = 0;

    while index < args.len() {
        let flag = args[index].as_str();
        let Some(value) = args.get(index + 1) else {
            return Err(ConfigError::InvalidArguments);
        };
        if value.is_empty() || value.starts_with("--") {
            return Err(ConfigError::InvalidArguments);
        }

        match flag {
            "--config" if config_path.is_none() => config_path = Some(value.clone()),
            "--credentials" if credentials_path.is_none() => credentials_path = Some(value.clone()),
            _ => return Err(ConfigError::InvalidArguments),
        }
        index += 2;
    }

    match (config_path, credentials_path) {
        (Some(config_path), Some(credentials_path)) => Ok(CliArgs {
            config_path,
            credentials_path,
        }),
        _ => Err(ConfigError::InvalidArguments),
    }
}

/// Load and validate a bounded, strict JSON service configuration document.
pub fn load_config(path: &Path) -> Result<AdmissionServiceConfig, ConfigError> {
    let bytes = read_bounded(path, MAX_CONFIG_FILE_BYTES)?;
    let config: AdmissionServiceConfig =
        serde_json::from_slice(&bytes).map_err(|_| ConfigError::InvalidJson)?;
    validate_service_config(&config)?;
    Ok(config)
}

/// Load the bounded credentials document and return its validated bearer token.
pub fn load_admin_token(path: &Path) -> Result<String, ConfigError> {
    let bytes = read_bounded(path, MAX_CREDENTIAL_FILE_BYTES)?;
    let credential: CredentialFile =
        serde_json::from_slice(&bytes).map_err(|_| ConfigError::InvalidJson)?;
    validate_admin_token(&credential.admin_token)?;
    Ok(credential.admin_token)
}

/// Validate all service and policy invariants before any listener is bound.
pub fn validate_service_config(config: &AdmissionServiceConfig) -> Result<(), ConfigError> {
    if config.configuration_version != "1" {
        return Err(ConfigError::InvalidConfiguration);
    }

    let bind_address: SocketAddr = config
        .bind_address
        .parse()
        .map_err(|_| ConfigError::InvalidConfiguration)?;
    if !bind_address.ip().is_loopback() || bind_address.port() == 0 {
        return Err(ConfigError::InvalidConfiguration);
    }

    if config.max_request_body_bytes == 0
        || config.max_request_body_bytes > MAX_REQUEST_BODY_BYTES
    {
        return Err(ConfigError::InvalidConfiguration);
    }

    if !valid_text_field(&config.audit_log_path, 4096) || config.audit_log_path.contains('\0') {
        return Err(ConfigError::InvalidConfiguration);
    }

    validate_policy(&config.policy)
}

fn validate_policy(policy: &AdmissionPolicy) -> Result<(), ConfigError> {
    if !valid_text_field(&policy.policy_id, 256) || !valid_text_field(&policy.policy_revision, 256) {
        return Err(ConfigError::InvalidConfiguration);
    }

    let mut executables = BTreeSet::new();
    for executable in &policy.allowed_executables {
        if !valid_executable(executable)
            || is_permanently_forbidden_executable(executable)
            || !executables.insert(executable.as_str())
        {
            return Err(ConfigError::InvalidConfiguration);
        }
    }

    let mut manifests = BTreeSet::new();
    for manifest in &policy.approved_manifests {
        if !valid_text_field(&manifest.workspace_id, 512)
            || !is_sha256_hex(&manifest.sha256)
            || !manifests.insert((manifest.workspace_id.as_str(), manifest.sha256.as_str()))
        {
            return Err(ConfigError::InvalidConfiguration);
        }
    }

    let mut artifacts = BTreeSet::new();
    for artifact in &policy.approved_artifacts {
        if !valid_text_field(&artifact.ecosystem, 64)
            || !valid_text_field(&artifact.name, 512)
            || !valid_pinned_version(&artifact.version)
            || !valid_https_registry(&artifact.registry_url)
            || !valid_text_field(&artifact.owner, 512)
            || !is_sha256_hex(&artifact.sha256)
            || !valid_text_field(&artifact.artifact_argument, 1024)
            || !artifacts.insert((
                artifact.ecosystem.as_str(),
                artifact.name.as_str(),
                artifact.version.as_str(),
                artifact.registry_url.as_str(),
            ))
        {
            return Err(ConfigError::InvalidConfiguration);
        }
    }

    Ok(())
}

fn validate_admin_token(token: &str) -> Result<(), ConfigError> {
    if token.len() < MIN_ADMIN_TOKEN_BYTES
        || token.len() > MAX_ADMIN_TOKEN_BYTES
        || !token.as_bytes().iter().all(|byte| (0x21..=0x7e).contains(byte))
    {
        return Err(ConfigError::InvalidCredential);
    }
    Ok(())
}

fn valid_text_field(value: &str, maximum_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum_bytes
        && !value.chars().any(char::is_control)
}

fn valid_executable(value: &str) -> bool {
    valid_text_field(value, 128)
        && !value.contains('/')
        && !value.contains('\\')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'+'))
}

fn is_permanently_forbidden_executable(executable: &str) -> bool {
    matches!(
        executable,
        "sh" | "bash"
            | "zsh"
            | "cmd"
            | "powershell"
            | "pwsh"
            | "curl"
            | "wget"
            | "aria2c"
            | "ftp"
            | "scp"
            | "npx"
            | "pnpx"
            | "bunx"
    )
}

fn valid_pinned_version(version: &str) -> bool {
    if !valid_text_field(version, 256) {
        return false;
    }
    let lowercase = version.to_ascii_lowercase();
    if matches!(lowercase.as_str(), "latest" | "main" | "master" | "head" | "stable" | "next") {
        return false;
    }
    !version
        .chars()
        .any(|character| character.is_whitespace() || "*^~<>=,|".contains(character))
}

fn valid_https_registry(registry_url: &str) -> bool {
    let Ok(url) = Url::parse(registry_url) else {
        return false;
    };
    url.scheme() == "https"
        && url.host_str().is_some()
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
}

fn read_bounded(path: &Path, maximum_bytes: u64) -> Result<Vec<u8>, ConfigError> {
    let file = File::open(PathBuf::from(path)).map_err(|_| ConfigError::Io)?;
    let mut bytes = Vec::new();
    file.take(maximum_bytes + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ConfigError::Io)?;
    if bytes.len() as u64 > maximum_bytes {
        return Err(ConfigError::FileTooLarge);
    }
    Ok(bytes)
}

#[allow(dead_code)]
fn _map_io_error(_: io::Error) -> ConfigError {
    ConfigError::Io
}
