from __future__ import annotations

from pathlib import Path
import re


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected one anchor, found {count}")
    return text.replace(old, new, 1)


def write(path: str, content: str) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")


core_path = Path("crates/waf-ids-core/src/lib.rs")
core = core_path.read_text(encoding="utf-8")

license_anchor = '''#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LicenseStatus {
    Unlicensed,
    Evaluation,
    Active,
    Expired,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RouteConfig {
'''
license_replacement = '''#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LicenseStatus {
    Unlicensed,
    Evaluation,
    Active,
    Expired,
}

/// Route-level authentication shape policy applied before upstream I/O.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizationPolicy {
    /// Preserve the existing generic proxy behavior.
    #[default]
    None,
    /// Require an RFC 6750 Bearer credential with LiteLLM's `sk-` virtual-key shape.
    LitellmVirtualKey,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RouteConfig {
'''
core = replace_once(core, license_anchor, license_replacement, "authorization enum")

field_anchor = '''    #[serde(default)]
    pub block_threshold: Option<u16>,
}
'''
field_replacement = '''    #[serde(default)]
    pub block_threshold: Option<u16>,
    /// Credential-class check performed before WAF scoring and upstream I/O.
    #[serde(default)]
    pub authorization_policy: AuthorizationPolicy,
}
'''
core = replace_once(core, field_anchor, field_replacement, "route authorization field")

literal_pattern = re.compile(r"(?m)^(?P<indent>\s*)block_threshold: (?P<value>[^,\n]+),$")
core, core_literal_count = literal_pattern.subn(
    lambda match: (
        f"{match.group('indent')}block_threshold: {match.group('value')},\n"
        f"{match.group('indent')}authorization_policy: AuthorizationPolicy::None,"
    ),
    core,
)
if core_literal_count < 1:
    raise SystemExit("core route literals: expected at least one literal")
core_path.write_text(core, encoding="utf-8")

root_path = Path("src/lib.rs")
root = root_path.read_text(encoding="utf-8")
root = replace_once(root, "    body::Bytes,\n", "    body::{Body, Bytes},\n", "axum Body import")
root = replace_once(
    root,
    "mod coraza_audit;\n",
    "mod coraza_audit;\nmod credential_guard;\n",
    "credential guard module",
)
root = replace_once(
    root,
    "    AuditLogEntry, BuyerEvidenceEndpoint, BuyerEvidenceManifest, BuyerEvidenceRuntimeCounts,\n",
    "    AuditLogEntry, AuthorizationPolicy, BuyerEvidenceEndpoint, BuyerEvidenceManifest,\n    BuyerEvidenceRuntimeCounts,\n",
    "AuthorizationPolicy re-export",
)

root, root_literal_count = literal_pattern.subn(
    lambda match: (
        f"{match.group('indent')}block_threshold: {match.group('value')},\n"
        f"{match.group('indent')}authorization_policy: AuthorizationPolicy::None,"
    ),
    root,
)
if root_literal_count < 1:
    raise SystemExit("root route literals: expected at least one literal")

guard_anchor = '''    let body_text = String::from_utf8_lossy(&body);
'''
guard_replacement = '''    if route.authorization_policy == AuthorizationPolicy::LitellmVirtualKey {
        if let Err(rejection) = credential_guard::validate_litellm_virtual_key(&headers) {
            record_event(
                &state,
                client_ip,
                Some(route.id.clone()),
                "auth_rejected",
                rejection.code().to_string(),
                0,
                gateway_path,
            )
            .await;
            return credential_guard::rejection_response(rejection);
        }
    }

    let body_text = String::from_utf8_lossy(&body);
'''
root = replace_once(root, guard_anchor, guard_replacement, "gateway credential guard")

proxy_call_anchor = '''    match proxy_request(&state, &route, &method, gateway_path, uri.query(), body).await {
'''
proxy_call_replacement = '''    match proxy_request(
        &state,
        &route,
        &method,
        gateway_path,
        uri.query(),
        &headers,
        body,
    )
    .await
    {
'''
root = replace_once(root, proxy_call_anchor, proxy_call_replacement, "proxy call headers")

proxy_signature_anchor = '''async fn proxy_request(
    state: &AppState,
    route: &RouteConfig,
    method: &Method,
    path: &str,
    query: Option<&str>,
    body: Bytes,
) -> Result<Response, String> {
'''
proxy_signature_replacement = '''async fn proxy_request(
    state: &AppState,
    route: &RouteConfig,
    method: &Method,
    path: &str,
    query: Option<&str>,
    request_headers: &HeaderMap,
    body: Bytes,
) -> Result<Response, String> {
'''
root = replace_once(root, proxy_signature_anchor, proxy_signature_replacement, "proxy signature")

proxy_body_anchor = '''    let response = state
        .http
        .request(method, target)
        .body(body)
        .send()
        .await
        .map_err(|error| format!("upstream request failed: {error}"))?;
    let status = StatusCode::from_u16(response.status().as_u16())
        .expect("reqwest upstream status codes are valid axum status codes");
    let bytes = response
        .bytes()
        .await
        .map_err(|error| format!("upstream body read failed: {error}"))?;
    Ok((status, bytes).into_response())
'''
proxy_body_replacement = '''    let request = credential_guard::forward_request_headers(
        request_headers,
        state.http.request(method, target).body(body),
    );
    let response = request
        .send()
        .await
        .map_err(|error| format!("upstream request failed: {error}"))?;
    let status = StatusCode::from_u16(response.status().as_u16())
        .expect("reqwest upstream status codes are valid axum status codes");
    let upstream_headers = response.headers().clone();
    let mut proxied = Response::new(Body::from_stream(response.bytes_stream()));
    *proxied.status_mut() = status;
    credential_guard::copy_response_headers(&upstream_headers, proxied.headers_mut());
    Ok(proxied)
'''
root = replace_once(root, proxy_body_anchor, proxy_body_replacement, "streaming proxy transport")
root_path.write_text(root, encoding="utf-8")

core_test = r'''use waf_ids_core::{AuthorizationPolicy, EnforcementMode, RouteConfig};

#[test]
fn route_policy_defaults_to_none_for_existing_json() {
    let route: RouteConfig = serde_json::from_value(serde_json::json!({
        "id": "legacy",
        "path_prefix": "/legacy",
        "upstream": "https://origin.example",
        "mode": "monitor",
        "enabled": true
    }))
    .expect("legacy route JSON");
    assert_eq!(route.authorization_policy, AuthorizationPolicy::None);
}

#[test]
fn litellm_policy_round_trips_with_stable_snake_case() {
    let route = RouteConfig {
        id: "llm".to_string(),
        path_prefix: "/llm".to_string(),
        upstream: "https://llm.example".to_string(),
        mode: EnforcementMode::Block,
        enabled: true,
        block_threshold: None,
        authorization_policy: AuthorizationPolicy::LitellmVirtualKey,
    };
    let value = serde_json::to_value(&route).expect("serialize route");
    assert_eq!(value["authorization_policy"], "litellm_virtual_key");
    let decoded: RouteConfig = serde_json::from_value(value).expect("deserialize route");
    assert_eq!(decoded, route);
}
'''
write("crates/waf-ids-core/tests/authorization_policy.rs", core_test)

readme_path = Path("README.md")
readme = readme_path.read_text(encoding="utf-8")
readme = replace_once(
    readme,
    "- monitor/block enforcement modes\n",
    "- monitor/block enforcement modes\n- route-level LiteLLM virtual-key credential-class enforcement\n",
    "README capability bullet",
)
readme_section = '''
### Protect a LiteLLM virtual-key route

Use a dedicated route policy when Wardnet fronts an OpenAI-compatible LiteLLM gateway:

```bash
curl -X POST http://127.0.0.1:8080/api/routes \\
  -H 'content-type: application/json' \\
  -H 'x-admin-token: dev-secret' \\
  -d '{
    "id": "litellm-dev",
    "path_prefix": "/llm",
    "upstream": "https://llm-gateway-dev.hyosungitx.com",
    "mode": "block",
    "enabled": true,
    "authorization_policy": "litellm_virtual_key"
  }'
```

Call the protected path with the original OpenAI-compatible suffix:

```bash
curl -X POST http://127.0.0.1:8080/gateway/llm/v1/chat/completions \\
  -H 'content-type: application/json' \\
  -H 'authorization: Bearer sk-REDACTED' \\
  -d '{"model":"auto","messages":[{"role":"user","content":"ping"}]}'
```

The guard rejects missing, duplicate, non-Bearer, malformed, oversized, and non-`sk-` credentials before upstream I/O. It never prepends `sk-` or authenticates the key locally; LiteLLM remains authoritative for key existence, revocation, team, model scope, quota, and budget. Rejections emit only non-secret reason codes. Accepted LLM responses are streamed so server-sent events are not buffered in full.

See `docs/security/litellm-virtual-key-ingress.md` and ADR-0011.

'''
readme = replace_once(
    readme,
    "Management writes are upserts:\n",
    readme_section + "Management writes are upserts:\n",
    "README LiteLLM section",
)
readme_path.write_text(readme, encoding="utf-8")

architecture_path = Path("docs/architecture.md")
architecture = architecture_path.read_text(encoding="utf-8")
marker = "## LiteLLM virtual-key ingress boundary"
if marker in architecture:
    raise SystemExit("architecture section already exists")
architecture += '''

## LiteLLM virtual-key ingress boundary

A route can opt into `authorization_policy: litellm_virtual_key`. The Rust hot path performs one bounded scan of at most 512 credential bytes after request admission and before WAF scoring or upstream network I/O. The check establishes only the expected credential class; LiteLLM remains the authority for actual authentication, revocation, budget, team, user, and model scope.

```text
caller
  → bounded request body
  → per-client admission
  → LiteLLM credential-class guard
  → WAF / IDS scoring
  → approved request-header projection
  → OpenAI-compatible upstream
  → approved response-header projection + streaming body
```

The transport does not forward cookies, forwarding-chain metadata, proxy credentials, host routing, transfer framing, or arbitrary headers. It preserves only LLM API metadata, W3C trace correlation, retry/rate-limit information, authentication challenges, and streaming content metadata. Rejected values are neither logged nor reflected; security events contain only stable reason codes.
'''
architecture_path.write_text(architecture, encoding="utf-8")

print(
    f"patched core literals={core_literal_count}, root literals={root_literal_count}; "
    "added guard policy, streaming proxy, docs, and tests"
)
