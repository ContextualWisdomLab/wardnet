use serde_json::{Map, Value};
use std::{
    ffi::{OsStr, OsString},
    path::PathBuf,
};

pub(crate) const CONFIGURATION_VERSION: &str = "configuration_version";
pub(crate) const LITELLM_PROXY_UPSTREAM_URL: &str = "litellm_proxy_upstream_url";
pub(crate) const LITELLM_PROXY_BIND_ADDRESS: &str = "litellm_proxy_bind_address";
pub(crate) const LITELLM_PROXY_MAX_BODY_BYTES: &str = "litellm_proxy_max_body_bytes";
pub(crate) const LITELLM_PROXY_CONNECT_TIMEOUT_SECONDS: &str =
    "litellm_proxy_connect_timeout_seconds";

/// Immutable process-local registry bootstrapped from a versioned JSON KV file.
///
/// The registry is the runtime source of operational configuration. Command-line
/// input supplies only the bootstrap file location; individual configuration
/// values are never read from raw environment variables.
#[derive(Debug, Clone)]
pub struct RuntimeConfigRegistry {
    values: Map<String, Value>,
}

impl RuntimeConfigRegistry {
    /// Load a JSON object from `path` into the process-local registry.
    pub fn from_json_file(path: impl Into<PathBuf>) -> Result<Self, String> {
        let path = path.into();
        let content = std::fs::read_to_string(&path).map_err(|error| {
            format!(
                "failed to read runtime configuration {}: {error}",
                path.display()
            )
        })?;
        Self::from_json_str(&content).map_err(|error| {
            format!(
                "runtime configuration {} is invalid: {error}",
                path.display()
            )
        })
    }

    pub(crate) fn from_json_str(content: &str) -> Result<Self, String> {
        let value: Value = serde_json::from_str(content)
            .map_err(|error| format!("configuration is not valid JSON: {error}"))?;
        let values = value
            .as_object()
            .cloned()
            .ok_or_else(|| "configuration root must be a JSON object".to_string())?;
        Ok(Self { values })
    }

    pub(crate) fn ensure_only(&self, allowed_keys: &[&str]) -> Result<(), String> {
        if let Some(key) = self
            .values
            .keys()
            .find(|key| !allowed_keys.contains(&key.as_str()))
        {
            return Err(format!("unknown runtime configuration key: {key}"));
        }
        Ok(())
    }

    pub(crate) fn required_string(&self, key: &str) -> Result<&str, String> {
        match self.values.get(key) {
            Some(Value::String(value)) if !value.is_empty() => Ok(value),
            Some(Value::String(_)) => Err(format!("runtime configuration {key} must not be empty")),
            Some(_) => Err(format!("runtime configuration {key} must be a string")),
            None => Err(format!("runtime configuration {key} is required")),
        }
    }

    pub(crate) fn string_or<'a>(&'a self, key: &str, default: &'a str) -> Result<&'a str, String> {
        match self.values.get(key) {
            Some(Value::String(value)) if !value.is_empty() => Ok(value),
            Some(Value::String(_)) => Err(format!("runtime configuration {key} must not be empty")),
            Some(_) => Err(format!("runtime configuration {key} must be a string")),
            None => Ok(default),
        }
    }

    pub(crate) fn usize_or(&self, key: &str, default: usize) -> Result<usize, String> {
        match self.values.get(key) {
            Some(Value::Number(value)) => {
                let value = value.as_u64().ok_or_else(|| {
                    format!("runtime configuration {key} must be an unsigned integer")
                })?;
                usize::try_from(value)
                    .map_err(|_| format!("runtime configuration {key} exceeds platform limits"))
            }
            Some(_) => Err(format!(
                "runtime configuration {key} must be an unsigned integer"
            )),
            None => Ok(default),
        }
    }

    pub(crate) fn u64_or(&self, key: &str, default: u64) -> Result<u64, String> {
        match self.values.get(key) {
            Some(Value::Number(value)) => value.as_u64().ok_or_else(|| {
                format!("runtime configuration {key} must be an unsigned integer")
            }),
            Some(_) => Err(format!(
                "runtime configuration {key} must be an unsigned integer"
            )),
            None => Ok(default),
        }
    }
}

/// Parse the mandatory `--config <path>` bootstrap argument.
pub fn configuration_path_from_args<I>(mut args: I) -> Result<PathBuf, String>
where
    I: Iterator<Item = OsString>,
{
    let flag = args
        .next()
        .ok_or_else(|| "usage: litellm-virtual-key-proxy --config <path>".to_string())?;
    if flag.as_os_str() != OsStr::new("--config") {
        return Err("expected --config <path>".to_string());
    }
    let path = args
        .next()
        .filter(|path| !path.is_empty())
        .map(PathBuf::from)
        .ok_or_else(|| "--config requires a non-empty path".to_string())?;
    if args.next().is_some() {
        return Err("unexpected arguments after --config <path>".to_string());
    }
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registry() -> RuntimeConfigRegistry {
        let content = serde_json::json!({
            CONFIGURATION_VERSION: "1",
            LITELLM_PROXY_UPSTREAM_URL: "https://llm.example",
            LITELLM_PROXY_MAX_BODY_BYTES: 4096
        })
        .to_string();
        RuntimeConfigRegistry::from_json_str(&content).unwrap()
    }

    #[test]
    fn reads_typed_values_and_defaults() {
        let registry = registry();
        assert_eq!(
            registry.required_string(LITELLM_PROXY_UPSTREAM_URL),
            Ok("https://llm.example")
        );
        assert_eq!(
            registry.string_or(LITELLM_PROXY_BIND_ADDRESS, "127.0.0.1:1"),
            Ok("127.0.0.1:1")
        );
        assert_eq!(
            registry.usize_or(LITELLM_PROXY_MAX_BODY_BYTES, 1),
            Ok(4096)
        );
        assert_eq!(
            registry.u64_or(LITELLM_PROXY_CONNECT_TIMEOUT_SECONDS, 10),
            Ok(10)
        );
    }

    #[test]
    fn rejects_root_type_unknown_key_and_wrong_value_types() {
        assert!(RuntimeConfigRegistry::from_json_str("[]").is_err());
        let unknown = serde_json::json!({"unknown": true}).to_string();
        let registry = RuntimeConfigRegistry::from_json_str(&unknown).unwrap();
        assert!(registry.ensure_only(&[CONFIGURATION_VERSION]).is_err());

        let wrong = serde_json::json!({
            "text": 1,
            "number": "1",
            "negative": -1
        })
        .to_string();
        let wrong = RuntimeConfigRegistry::from_json_str(&wrong).unwrap();
        assert!(wrong.required_string("text").is_err());
        assert!(wrong.usize_or("number", 1).is_err());
        assert!(wrong.u64_or("negative", 1).is_err());
    }

    #[test]
    fn parses_exact_config_argument_contract() {
        assert_eq!(
            configuration_path_from_args(
                ["--config", "/etc/wardnet/proxy.json"]
                    .into_iter()
                    .map(OsString::from)
            ),
            Ok(PathBuf::from("/etc/wardnet/proxy.json"))
        );
        assert!(configuration_path_from_args(std::iter::empty()).is_err());
        assert!(
            configuration_path_from_args(["--wrong", "file"].into_iter().map(OsString::from))
                .is_err()
        );
        assert!(
            configuration_path_from_args(
                ["--config", "file", "extra"]
                    .into_iter()
                    .map(OsString::from)
            )
            .is_err()
        );
    }
}
