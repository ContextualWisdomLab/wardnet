#[path = "litellm_credential.rs"]
mod litellm_credential;

pub(crate) use litellm_credential::{CredentialRejection, validate_litellm_virtual_key};

use axum::{
    Json,
    http::{
        HeaderMap, HeaderName, HeaderValue, StatusCode,
        header::{CACHE_CONTROL, PRAGMA, WWW_AUTHENTICATE},
    },
    response::{IntoResponse, Response},
};

const MISSING_CHALLENGE: &str = "Bearer realm=\"litellm\"";
const INVALID_CHALLENGE: &str = "Bearer realm=\"litellm\", error=\"invalid_token\", error_description=\"A LiteLLM virtual key is required\"";

fn challenge(rejection: CredentialRejection) -> &'static str {
    match rejection {
        CredentialRejection::Missing => MISSING_CHALLENGE,
        CredentialRejection::Ambiguous
        | CredentialRejection::InvalidScheme
        | CredentialRejection::InvalidShape => INVALID_CHALLENGE,
    }
}

/// Build a cache-safe RFC 6750 authentication failure without reflecting the
/// supplied credential or any masked fragment of it.
pub(crate) fn rejection_response(rejection: CredentialRejection) -> Response {
    let mut response = (
        StatusCode::UNAUTHORIZED,
        Json(serde_json::json!({
            "error": {
                "type": "authentication_error",
                "code": rejection.code(),
                "message": "LLM gateway credential rejected"
            }
        })),
    )
        .into_response();
    response.headers_mut().insert(
        WWW_AUTHENTICATE,
        HeaderValue::from_static(challenge(rejection)),
    );
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(PRAGMA, HeaderValue::from_static("no-cache"));
    response
}

/// Forward only the request metadata required by OpenAI-compatible LLM APIs.
/// Cookies, proxy headers, host routing, transfer framing, forwarding-chain
/// headers, trace baggage, and arbitrary extension headers are intentionally
/// not copied.
pub(crate) fn forward_request_headers(
    source: &HeaderMap,
    mut request: reqwest::RequestBuilder,
) -> reqwest::RequestBuilder {
    for (name, value) in source {
        if request_header_allowed(name) {
            request = request.header(name.clone(), value.clone());
        }
    }
    request
}

fn request_header_allowed(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "authorization"
            | "accept"
            | "content-type"
            | "content-encoding"
            | "user-agent"
            | "openai-organization"
            | "openai-project"
            | "x-request-id"
            | "traceparent"
            | "tracestate"
    )
}

/// Copy a bounded set of upstream response headers needed for streaming,
/// retries, request correlation, and LiteLLM/OpenAI rate-limit reporting.
pub(crate) fn copy_response_headers(source: &HeaderMap, target: &mut HeaderMap) {
    for (name, value) in source {
        if response_header_allowed(name) {
            target.append(name.clone(), value.clone());
        }
    }
}

fn response_header_allowed(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "content-type"
            | "content-encoding"
            | "cache-control"
            | "etag"
            | "retry-after"
            | "www-authenticate"
            | "x-request-id"
            | "openai-processing-ms"
            | "openai-version"
            | "traceparent"
            | "tracestate"
    ) || name.as_str().starts_with("x-ratelimit-")
        || name.as_str().starts_with("x-litellm-")
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{
        HeaderValue,
        header::{AUTHORIZATION, CONTENT_TYPE, COOKIE},
    };

    #[test]
    fn rejection_response_is_non_reflective_and_cache_safe() {
        let response = rejection_response(CredentialRejection::InvalidShape);
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response.headers().get(CACHE_CONTROL),
            Some(&HeaderValue::from_static("no-store"))
        );
        assert_eq!(
            response.headers().get(PRAGMA),
            Some(&HeaderValue::from_static("no-cache"))
        );
        assert!(
            response
                .headers()
                .get(WWW_AUTHENTICATE)
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| value.contains("invalid_token"))
        );

        let missing = rejection_response(CredentialRejection::Missing);
        assert!(
            missing
                .headers()
                .get(WWW_AUTHENTICATE)
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| !value.contains("invalid_token"))
        );
    }

    #[test]
    fn request_header_policy_forwards_only_approved_metadata() {
        let mut source = HeaderMap::new();
        source.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer sk-test-placeholder"),
        );
        source.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        source.insert(COOKIE, HeaderValue::from_static("private=1"));
        source.insert("baggage", HeaderValue::from_static("customer=private"));
        source.insert("x-litellm-private", HeaderValue::from_static("private"));

        let request = forward_request_headers(
            &source,
            reqwest::Client::new().post("https://example.invalid/v1/models"),
        )
        .build()
        .expect("build projected request");
        assert!(request.headers().contains_key(AUTHORIZATION));
        assert!(request.headers().contains_key(CONTENT_TYPE));
        assert!(!request.headers().contains_key(COOKIE));
        assert!(!request.headers().contains_key("baggage"));
        assert!(!request.headers().contains_key("x-litellm-private"));
    }

    #[test]
    fn response_header_policy_excludes_credentials_and_cookies() {
        let mut source = HeaderMap::new();
        source.insert(CONTENT_TYPE, HeaderValue::from_static("text/event-stream"));
        source.insert(
            "x-ratelimit-remaining-requests",
            HeaderValue::from_static("9"),
        );
        source.insert(COOKIE, HeaderValue::from_static("private=1"));
        source.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer sk-test-placeholder"),
        );
        let mut target = HeaderMap::new();
        copy_response_headers(&source, &mut target);
        assert_eq!(
            target.get(CONTENT_TYPE),
            Some(&HeaderValue::from_static("text/event-stream"))
        );
        assert_eq!(
            target.get("x-ratelimit-remaining-requests"),
            Some(&HeaderValue::from_static("9"))
        );
        assert!(!target.contains_key(COOKIE));
        assert!(!target.contains_key(AUTHORIZATION));
    }
}
