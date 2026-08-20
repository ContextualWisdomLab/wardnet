//! Dedicated high-throughput reverse proxy for a LiteLLM virtual-key boundary.
//!
//! The proxy performs one bounded credential-shape scan before any upstream
//! I/O, forwards only approved end-to-end headers, and streams upstream bodies
//! without accumulating complete LLM responses in memory.

#[path = "credential_guard.rs"]
mod credential_guard;
#[path = "runtime_config.rs"]
mod runtime_config;

pub use runtime_config::{RuntimeConfigRegistry, configuration_path_from_args};

use axum::{
    Json, Router,
    body::{Body, Bytes},
    extract::{DefaultBodyLimit, State},
    http::{
        HeaderMap, HeaderValue, Method, StatusCode, Uri,
        header::{ALLOW, CACHE_CONTROL},
    },
    response::{IntoResponse, Response},
    routing::get,
};
use reqwest::{Client, Url, redirect::Policy};
use runtime_config::{
    CONFIGURATION_VERSION, LITELLM_PROXY_BIND_ADDRESS, LITELLM_PROXY_CONNECT_TIMEOUT_SECONDS,
    LITELLM_PROXY_MAX_BODY_BYTES, LITELLM_PROXY_UPSTREAM_URL,
};
use serde::Serialize;
use std::{
    error::Error,
    net::{IpAddr, SocketAddr},
    time::Duration,
};

const DEFAULT_BIND_ADDRESS: &str = "127.0.0.1:8090";
const DEFAULT_MAX_BODY_BYTES: usize = 16 * 1024 * 1024;
const DEFAULT_CONNECT_TIMEOUT_SECONDS: u64 = 10;
const SUPPORTED_CONFIGURATION_VERSION: &str = "1";
const ALLOWED_METHODS: &str = "GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS";
const ALLOWED_CONFIG_KEYS: [&str; 5] = [
    CONFIGURATION_VERSION,
    LITELLM_PROXY_UPSTREAM_URL,
    LITELLM_PROXY_BIND_ADDRESS,
    LITELLM_PROXY_MAX_BODY_BYTES,
    LITELLM_PROXY_CONNECT_TIMEOUT_SECONDS,
];

/// Runtime configuration for the dedicated LiteLLM ingress proxy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyConfig {
    /// Local listen address for the sidecar or edge deployment.
    pub bind_address: SocketAddr,
    /// Fixed LiteLLM upstream origin. Request paths and queries are appended.
    pub upstream_url: Url,
    /// Maximum accepted request-body size before the handler runs.
    pub max_body_bytes: usize,
    /// Maximum duration allowed to establish the upstream connection.
    pub connect_timeout: Duration,
}

impl ProxyConfig {
    /// Resolve the immutable proxy configuration from a process-local registry.
    pub fn from_registry(registry: &RuntimeConfigRegistry) -> Result<Self, String> {
        registry.ensure_only(&ALLOWED_CONFIG_KEYS)?;
        let version = registry.required_string(CONFIGURATION_VERSION)?;
        if version != SUPPORTED_CONFIGURATION_VERSION {
            return Err(format!(
                "unsupported configuration_version {version}; expected {SUPPORTED_CONFIGURATION_VERSION}"
            ));
        }
        let upstream = registry.required_string(LITELLM_PROXY_UPSTREAM_URL)?;
        let bind_address = registry
            .string_or(LITELLM_PROXY_BIND_ADDRESS, DEFAULT_BIND_ADDRESS)?
            .parse::<SocketAddr>()
            .map_err(|error| format!("invalid {LITELLM_PROXY_BIND_ADDRESS}: {error}"))?;
        let max_body_bytes = registry.usize_or(
            LITELLM_PROXY_MAX_BODY_BYTES,
            DEFAULT_MAX_BODY_BYTES,
        )?;
        let connect_timeout_seconds = registry.u64_or(
            LITELLM_PROXY_CONNECT_TIMEOUT_SECONDS,
            DEFAULT_CONNECT_TIMEOUT_SECONDS,
        )?;
        Self::new(
            bind_address,
            upstream,
            max_body_bytes,
            Duration::from_secs(connect_timeout_seconds),
        )
    }

    /// Construct and validate an explicit configuration.
    pub fn new(
        bind_address: SocketAddr,
        upstream_url: impl AsRef<str>,
        max_body_bytes: usize,
        connect_timeout: Duration,
    ) -> Result<Self, String> {
        if max_body_bytes == 0 {
            return Err("max_body_bytes must be greater than 0".to_string());
        }
        if connect_timeout.is_zero() {
            return Err("connect_timeout must be greater than 0".to_string());
        }
        let upstream_url = validate_upstream_url(upstream_url.as_ref())?;
        Ok(Self {
            bind_address,
            upstream_url,
            max_body_bytes,
            connect_timeout,
        })
    }
}

/// Cloneable application state shared by proxy requests.
#[derive(Clone)]
pub struct ProxyState {
    client: Client,
    upstream_url: Url,
    max_body_bytes: usize,
}

impl ProxyState {
    /// Build a no-redirect, no-system-proxy, connection-pooled HTTP client.
    pub fn new(config: &ProxyConfig) -> Result<Self, String> {
        let client = Client::builder()
            .no_proxy()
            .redirect(Policy::none())
            .connect_timeout(config.connect_timeout)
            .pool_idle_timeout(Duration::from_secs(90))
            .pool_max_idle_per_host(256)
            .tcp_keepalive(Duration::from_secs(60))
            .build()
            .map_err(|error| format!("failed to build upstream client: {error}"))?;
        Ok(Self {
            client,
            upstream_url: config.upstream_url.clone(),
            max_body_bytes: config.max_body_bytes,
        })
    }

    fn target(&self, uri: &Uri) -> Result<Url, String> {
        let base = self.upstream_url.as_str().trim_end_matches('/');
        let mut target = format!("{base}{}", uri.path());
        if let Some(query) = uri.query().filter(|query| !query.is_empty()) {
            target.push('?');
            target.push_str(query);
        }
        Url::parse(&target).map_err(|error| format!("invalid upstream target: {error}"))
    }
}

#[derive(Serialize)]
struct HealthBody<'a> {
    status: &'a str,
    credential_policy: &'a str,
    configuration_version: &'a str,
    upstream_origin: String,
    max_body_bytes: usize,
}

/// Build the standalone LiteLLM proxy router.
pub fn build_router(state: ProxyState) -> Router {
    let max_body_bytes = state.max_body_bytes;
    Router::new()
        .route("/healthz", get(healthz))
        .fallback(proxy_request)
        .layer(DefaultBodyLimit::max(max_body_bytes))
        .with_state(state)
}

async fn healthz(State(state): State<ProxyState>) -> Json<HealthBody<'static>> {
    Json(HealthBody {
        status: "ok",
        credential_policy: "litellm_virtual_key",
        configuration_version: SUPPORTED_CONFIGURATION_VERSION,
        upstream_origin: upstream_origin(&state.upstream_url),
        max_body_bytes: state.max_body_bytes,
    })
}

async fn proxy_request(
    State(state): State<ProxyState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Err(rejection) = credential_guard::validate_litellm_virtual_key(&headers) {
        emit_auth_rejection(rejection.code(), uri.path());
        return credential_guard::rejection_response(rejection);
    }
    if !method_allowed(&method) {
        return method_not_allowed();
    }

    let target = match state.target(&uri) {
        Ok(target) => target,
        Err(_) => {
            emit_proxy_event("proxy_target_error", "invalid_upstream_target", uri.path());
            return proxy_error(
                StatusCode::BAD_GATEWAY,
                "invalid_upstream_target",
                "LiteLLM upstream target could not be constructed",
            );
        }
    };
    let upstream_method = match reqwest::Method::from_bytes(method.as_str().as_bytes()) {
        Ok(method) => method,
        Err(_) => return method_not_allowed(),
    };
    let request = credential_guard::forward_request_headers(
        &headers,
        state.client.request(upstream_method, target).body(body),
    );
    let upstream = match request.send().await {
        Ok(response) => response,
        Err(error) => {
            eprintln!(
                "{}",
                serde_json::json!({
                    "event_type": "upstream_transport_error",
                    "path": uri.path(),
                    "reason": "upstream_request_failed",
                    "error_class": error_class(&error)
                })
            );
            return proxy_error(
                StatusCode::BAD_GATEWAY,
                "upstream_request_failed",
                "LiteLLM upstream request failed",
            );
        }
    };

    if upstream.status().is_redirection() {
        emit_proxy_event(
            "upstream_policy_rejection",
            "upstream_redirect_rejected",
            uri.path(),
        );
        return proxy_error(
            StatusCode::BAD_GATEWAY,
            "upstream_redirect_rejected",
            "LiteLLM upstream redirect rejected",
        );
    }

    let status = StatusCode::from_u16(upstream.status().as_u16())
        .expect("reqwest upstream status codes are valid HTTP status codes");
    let upstream_headers = upstream.headers().clone();
    let mut response = Response::new(Body::from_stream(upstream.bytes_stream()));
    *response.status_mut() = status;
    credential_guard::copy_response_headers(&upstream_headers, response.headers_mut());
    response
}

fn method_allowed(method: &Method) -> bool {
    method == Method::GET
        || method == Method::POST
        || method == Method::PUT
        || method == Method::PATCH
        || method == Method::DELETE
        || method == Method::HEAD
        || method == Method::OPTIONS
}

fn method_not_allowed() -> Response {
    let mut response = proxy_error(
        StatusCode::METHOD_NOT_ALLOWED,
        "unsupported_http_method",
        "Unsupported HTTP method",
    );
    response
        .headers_mut()
        .insert(ALLOW, HeaderValue::from_static(ALLOWED_METHODS));
    response
}

fn emit_auth_rejection(reason: &str, path: &str) {
    emit_proxy_event("llm_auth_rejected", reason, path);
}

fn emit_proxy_event(event_type: &str, reason: &str, path: &str) {
    eprintln!(
        "{}",
        serde_json::json!({
            "event_type": event_type,
            "reason": reason,
            "path": path
        })
    );
}

fn proxy_error(status: StatusCode, code: &str, message: impl Into<String>) -> Response {
    let mut response = (
        status,
        Json(serde_json::json!({
            "error": {
                "type": "proxy_error",
                "code": code,
                "message": message.into()
            }
        })),
    )
        .into_response();
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn validate_upstream_url(raw: &str) -> Result<Url, String> {
    let url = Url::parse(raw).map_err(|error| format!("invalid upstream URL: {error}"))?;
    if !url.username().is_empty() || url.password().is_some() {
        return Err("upstream URL must not contain credentials".to_string());
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err("upstream URL must not contain a query or fragment".to_string());
    }
    if url.path() != "/" {
        return Err("upstream URL must be an origin without a path prefix".to_string());
    }
    match url.scheme() {
        "https" => {}
        "http" if is_loopback_host(url.host_str()) => {}
        "http" => return Err("plaintext upstream is allowed only for loopback tests".to_string()),
        _ => return Err("upstream URL must use https:// or loopback http://".to_string()),
    }
    if url.host_str().is_none() {
        return Err("upstream URL must include a host".to_string());
    }
    Ok(url)
}

fn is_loopback_host(host: Option<&str>) -> bool {
    let Some(host) = host else {
        return false;
    };
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<IpAddr>()
            .map(|address| address.is_loopback())
            .unwrap_or(false)
}

fn upstream_origin(url: &Url) -> String {
    url.origin().ascii_serialization()
}

fn error_class(error: &reqwest::Error) -> &'static str {
    if error.is_connect() {
        "connect"
    } else if error.is_timeout() {
        "timeout"
    } else if error.is_request() {
        "request"
    } else if error.is_body() {
        "body"
    } else {
        "other"
    }
}

/// Bind and serve the dedicated proxy until `shutdown` resolves.
pub async fn serve(
    config: ProxyConfig,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> Result<(), Box<dyn Error>> {
    let state = ProxyState::new(&config)
        .map_err(|message| std::io::Error::new(std::io::ErrorKind::InvalidInput, message))?;
    let listener = tokio::net::TcpListener::bind(config.bind_address).await?;
    let local_address = listener.local_addr()?;
    println!("litellm-virtual-key-proxy listening on http://{local_address}");
    axum::serve(listener, build_router(state))
        .with_graceful_shutdown(shutdown)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registry(content: &str) -> RuntimeConfigRegistry {
        RuntimeConfigRegistry::from_json_str(content).unwrap()
    }

    #[test]
    fn resolves_registry_configuration_and_defaults() {
        let config = ProxyConfig::from_registry(&registry(
            r#"{
                "configuration_version": "1",
                "litellm_proxy_upstream_url": "https://llm.example"
            }"#,
        ))
        .unwrap();
        assert_eq!(config.bind_address, "127.0.0.1:8090".parse().unwrap());
        assert_eq!(config.max_body_bytes, DEFAULT_MAX_BODY_BYTES);
        assert_eq!(
            config.connect_timeout,
            Duration::from_secs(DEFAULT_CONNECT_TIMEOUT_SECONDS)
        );

        assert!(
            ProxyConfig::from_registry(&registry(
                r#"{
                    "configuration_version": "2",
                    "litellm_proxy_upstream_url": "https://llm.example"
                }"#
            ))
            .is_err()
        );
        assert!(
            ProxyConfig::from_registry(&registry(
                r#"{
                    "configuration_version": "1",
                    "litellm_proxy_upstream_url": "https://llm.example",
                    "typo_limit": 1
                }"#
            ))
            .is_err()
        );
    }

    #[test]
    fn validates_upstream_security_boundary() {
        assert!(validate_upstream_url("https://llm.example").is_ok());
        assert!(validate_upstream_url("http://127.0.0.1:4000").is_ok());
        assert!(validate_upstream_url("http://localhost:4000/base").is_err());
        assert!(validate_upstream_url("http://llm.example").is_err());
        assert!(validate_upstream_url("https://user:secret@llm.example").is_err());
        assert!(validate_upstream_url("https://llm.example?key=value").is_err());
        assert!(validate_upstream_url("file:///tmp/socket").is_err());
    }

    #[test]
    fn appends_request_path_and_query_to_fixed_origin() {
        let config = ProxyConfig::new(
            "127.0.0.1:0".parse().unwrap(),
            "https://llm.example",
            1024,
            Duration::from_secs(1),
        )
        .unwrap();
        let state = ProxyState::new(&config).unwrap();
        let target = state
            .target(&"/v1/models?team=a".parse::<Uri>().unwrap())
            .unwrap();
        assert_eq!(target.as_str(), "https://llm.example/v1/models?team=a");
    }

    #[test]
    fn validates_positive_bounds_and_methods() {
        assert!(
            ProxyConfig::new(
                "127.0.0.1:0".parse().unwrap(),
                "https://llm.example",
                0,
                Duration::from_secs(1)
            )
            .is_err()
        );
        assert!(
            ProxyConfig::new(
                "127.0.0.1:0".parse().unwrap(),
                "https://llm.example",
                1,
                Duration::ZERO
            )
            .is_err()
        );
        for method in [
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
            Method::HEAD,
            Method::OPTIONS,
        ] {
            assert!(method_allowed(&method));
        }
        assert!(!method_allowed(&Method::CONNECT));
        assert!(!method_allowed(&Method::TRACE));
    }
}
