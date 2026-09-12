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
///
/// As of September 2026, this public type no longer carries a
/// `credentials_path` field. External callers that previously built
/// `RuntimeConfiguration` struct literals with that field must now bootstrap
/// secret-file selection through [`CredentialRegistry::bootstrap_from_env`] or
/// [`CredentialRegistry::bootstrap_secrets`] and keep
/// `RuntimeConfiguration` limited to non-secret listener, DNSBL, and retention
/// settings.
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

    /// Build the same runtime snapshot from an injected lookup source.
    ///
    /// Tests use this seam to prove startup consumes one immutable bootstrap
    /// view without mutating or re-reading process environment state.
    fn from_lookup(
        mut lookup: impl FnMut(&str) -> Option<String>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let bind_addr = lookup("BIND_ADDR").unwrap_or_else(|| Self::DEFAULT_BIND_ADDR.to_string());
        let state_path = lookup("WAF_IDS_STATE_PATH")
            .filter(|path| !path.trim().is_empty())
            .map(PathBuf::from);
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
/// Tokenize the Rust syntax needed by the architecture fitness rule while
/// discarding comments and string literal bodies so documentation or fixture
/// strings cannot be mistaken for executable environment access. Apostrophes
/// remain punctuation: treating a lifetime like `'a` as a character literal
/// can otherwise hide executable tokens until a later apostrophe on the line.
fn rust_syntax_tokens(source: &str) -> Vec<String> {
    fn raw_string_end(bytes: &[u8], start: usize) -> Option<usize> {
        let mut cursor = start;
        if bytes.get(cursor) == Some(&b'b') {
            cursor += 1;
        }
        if bytes.get(cursor) != Some(&b'r') {
            return None;
        }
        cursor += 1;
        let hash_start = cursor;
        while bytes.get(cursor) == Some(&b'#') {
            cursor += 1;
        }
        let hash_count = cursor - hash_start;
        if bytes.get(cursor) != Some(&b'"') {
            return None;
        }
        cursor += 1;
        while cursor < bytes.len() {
            if bytes[cursor] == b'"'
                && bytes
                    .get(cursor + 1..cursor + 1 + hash_count)
                    .is_some_and(|suffix| suffix.iter().all(|byte| *byte == b'#'))
            {
                return Some(cursor + 1 + hash_count);
            }
            cursor += 1;
        }
        Some(bytes.len())
    }

    let bytes = source.as_bytes();
    let mut tokens = Vec::new();
    let mut cursor = 0usize;
    while cursor < bytes.len() {
        if bytes[cursor].is_ascii_whitespace() {
            cursor += 1;
            continue;
        }
        if bytes[cursor] == b'/' && bytes.get(cursor + 1) == Some(&b'/') {
            cursor += 2;
            while cursor < bytes.len() && bytes[cursor] != b'\n' {
                cursor += 1;
            }
            continue;
        }
        if bytes[cursor] == b'/' && bytes.get(cursor + 1) == Some(&b'*') {
            cursor += 2;
            let mut depth = 1usize;
            while cursor < bytes.len() && depth > 0 {
                if bytes[cursor] == b'/' && bytes.get(cursor + 1) == Some(&b'*') {
                    depth += 1;
                    cursor += 2;
                } else if bytes[cursor] == b'*' && bytes.get(cursor + 1) == Some(&b'/') {
                    depth -= 1;
                    cursor += 2;
                } else {
                    cursor += 1;
                }
            }
            continue;
        }
        if (bytes[cursor] == b'r'
            || (bytes[cursor] == b'b' && bytes.get(cursor + 1) == Some(&b'r')))
            && let Some(end) = raw_string_end(bytes, cursor)
        {
            cursor = end;
            continue;
        }
        if bytes[cursor] == b'"' {
            cursor += 1;
            while cursor < bytes.len() {
                match bytes[cursor] {
                    b'\\' => cursor = (cursor + 2).min(bytes.len()),
                    b'"' => {
                        cursor += 1;
                        break;
                    }
                    _ => cursor += 1,
                }
            }
            continue;
        }
        if bytes[cursor].is_ascii_alphabetic() || bytes[cursor] == b'_' {
            let start = cursor;
            cursor += 1;
            while cursor < bytes.len()
                && (bytes[cursor].is_ascii_alphanumeric() || bytes[cursor] == b'_')
            {
                cursor += 1;
            }
            tokens.push(source[start..cursor].to_string());
            continue;
        }
        if bytes[cursor] == b':' && bytes.get(cursor + 1) == Some(&b':') {
            tokens.push("::".to_string());
            cursor += 2;
            continue;
        }
        tokens.push((bytes[cursor] as char).to_string());
        cursor += 1;
    }
    tokens
}

#[cfg(test)]
/// Return whether one parsed `use` statement imports `std::env` or creates an
/// alias for the `std` root that could hide a later environment read.
fn use_statement_exposes_runtime_env(statement: &[String]) -> bool {
    let mut cursor = usize::from(statement.first().is_some_and(|token| token == "::"));
    if statement.get(cursor).map(String::as_str) != Some("std") {
        return false;
    }
    cursor += 1;
    if statement.get(cursor).map(String::as_str) == Some("as") {
        return true;
    }
    if statement.get(cursor).map(String::as_str) != Some("::") {
        return false;
    }
    cursor += 1;
    match statement.get(cursor).map(String::as_str) {
        Some("env") => true,
        Some("{") => {
            cursor += 1;
            let mut depth = 0usize;
            let mut entry = Vec::new();
            while let Some(token) = statement.get(cursor) {
                match token.as_str() {
                    "{" | "(" | "[" => {
                        depth += 1;
                        entry.push(token.as_str());
                    }
                    "}" if depth == 0 => {
                        if use_group_entry_exposes_runtime_env(&entry) {
                            return true;
                        }
                        break;
                    }
                    "}" | ")" | "]" => {
                        depth = depth.saturating_sub(1);
                        entry.push(token.as_str());
                    }
                    "," if depth == 0 => {
                        if use_group_entry_exposes_runtime_env(&entry) {
                            return true;
                        }
                        entry.clear();
                    }
                    _ => entry.push(token.as_str()),
                }
                cursor += 1;
            }
            false
        }
        _ => false,
    }
}

#[cfg(test)]
/// Evaluate one top-level `std::{...}` use-tree entry for the two forbidden
/// roots: `env` itself or `self as <alias>` for a hidden `std` root.
fn use_group_entry_exposes_runtime_env(entry: &[&str]) -> bool {
    matches!(entry.first().copied(), Some("env"))
        || matches!(entry, ["self", "as", alias, ..] if !alias.is_empty())
}

#[cfg(test)]
/// Detect executable Rust syntax that reads process environment outside the
/// approved bootstrap adapters.
///
/// The parser deliberately operates on tokens rather than substrings: comments
/// and normal/raw string literals are discarded; `use` trees and simple
/// function-item aliases are then evaluated structurally.
fn source_uses_runtime_env(source: &str) -> bool {
    let tokens = rust_syntax_tokens(source);

    for (index, token) in tokens.iter().enumerate() {
        if token == "use" {
            let end = tokens[index + 1..]
                .iter()
                .position(|candidate| candidate == ";")
                .map(|offset| index + 1 + offset)
                .unwrap_or(tokens.len());
            if use_statement_exposes_runtime_env(&tokens[index + 1..end]) {
                return true;
            }
        }
        if token == "extern"
            && tokens.get(index + 1).map(String::as_str) == Some("crate")
            && tokens.get(index + 2).map(String::as_str) == Some("std")
            && tokens.get(index + 3).map(String::as_str) == Some("as")
        {
            return true;
        }
        if tokens.get(index).map(String::as_str) == Some("std")
            && tokens.get(index + 1).map(String::as_str) == Some("::")
            && tokens.get(index + 2).map(String::as_str) == Some("env")
            && tokens.get(index + 3).map(String::as_str) == Some("::")
            && matches!(
                tokens.get(index + 4).map(String::as_str),
                Some("var" | "var_os")
            )
            && tokens.get(index + 5).map(String::as_str) == Some("(")
        {
            return true;
        }
    }

    let mut function_aliases = std::collections::HashSet::new();
    for index in 0..tokens.len() {
        if tokens[index] != "let" {
            continue;
        }
        let mut binding = index + 1;
        if tokens.get(binding).map(String::as_str) == Some("mut") {
            binding += 1;
        }
        let Some(alias) = tokens.get(binding).filter(|name| {
            name.as_bytes()
                .first()
                .is_some_and(|byte| byte.is_ascii_alphabetic() || *byte == b'_')
        }) else {
            continue;
        };
        let statement_end = tokens[binding + 1..]
            .iter()
            .position(|token| token == ";")
            .map(|offset| binding + 1 + offset)
            .unwrap_or(tokens.len());
        let Some(equals) = tokens[binding + 1..statement_end]
            .iter()
            .position(|token| token == "=")
            .map(|offset| binding + 1 + offset)
        else {
            continue;
        };
        let rhs = equals + 1;
        let aliases_env_function = tokens.get(rhs).map(String::as_str) == Some("std")
            && tokens.get(rhs + 1).map(String::as_str) == Some("::")
            && tokens.get(rhs + 2).map(String::as_str) == Some("env")
            && tokens.get(rhs + 3).map(String::as_str) == Some("::")
            && matches!(
                tokens.get(rhs + 4).map(String::as_str),
                Some("var" | "var_os")
            )
            && tokens.get(rhs + 5).is_some_and(|token| token == ";");
        let aliases_existing_function = tokens
            .get(rhs)
            .is_some_and(|candidate| function_aliases.contains(candidate))
            && tokens.get(rhs + 1).is_some_and(|token| token == ";");
        if aliases_env_function || aliases_existing_function {
            function_aliases.insert(alias.clone());
        }
    }

    tokens.windows(2).any(|window| {
        function_aliases.contains(&window[0]) && window[1] == "("
    })
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
    }

    #[test]
    /// Blank state-path bootstrap input must preserve protected-main's in-memory semantics.
    fn runtime_configuration_ignores_blank_state_path() {
        for raw in ["", "   ", "\t"] {
            let config = runtime_from_pairs(&[("WAF_IDS_STATE_PATH", raw)]).unwrap();
            assert_eq!(
                config.state_path,
                None,
                "blank state path {raw:?} must be ignored"
            );
        }
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
    /// AppConfig combines non-secret runtime values with registry-backed secrets.
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
    /// The syntax detector rejects direct calls, use aliases, and function-item aliases.
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
        assert!(source_uses_runtime_env(
            "use std as standard; fn bypass() { let _ = standard::env::var(\"BIND_ADDR\"); }"
        ));
        assert!(source_uses_runtime_env(
            "use ::std::env as process_env; fn bypass() { let _ = process_env::var(\"BIND_ADDR\"); }"
        ));
        assert!(source_uses_runtime_env(
            "use std::{self as standard}; fn bypass() { let _ = standard::env::var(\"BIND_ADDR\"); }"
        ));
        assert!(source_uses_runtime_env(
            "extern crate std as standard; fn bypass() { let _ = standard::env::var(\"BIND_ADDR\"); }"
        ));
        assert!(source_uses_runtime_env(
            "fn bypass() { let read = std::env::var; let _ = read(\"BIND_ADDR\"); }"
        ));
        assert!(source_uses_runtime_env(
            "fn bypass() { let read = std::env::var_os; let read_again = read; let _ = read_again(\"BIND_ADDR\"); }"
        ));
        assert!(!source_uses_runtime_env("use std::fmt; fn harmless() {}"));
    }

    #[test]
    /// Lifetimes must not be consumed as if they were character literals.
    fn runtime_env_syntax_detector_keeps_lifetime_delimiters_visible() {
        assert!(source_uses_runtime_env(
            "fn bypass<'a>() { let _ = std::env::var(\"BIND_ADDR\"); let _: &'a str = \"\"; }"
        ));
    }

    #[test]
    /// Comments and literal text that mention env APIs are not executable access.
    fn runtime_env_syntax_detector_ignores_comments_and_literals() {
        let source = r###"
            // let read = std::env::var;
            /* use std::env as process_env; */
            const NORMAL: &str = "std::env::var(\"BIND_ADDR\")";
            const RAW: &str = r#"use std::env; std::env::var_os(\"X\")"#;
            fn harmless() { let value = 'x'; let _ = (NORMAL, RAW, value); }
        "###;
        assert!(!source_uses_runtime_env(source));
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
