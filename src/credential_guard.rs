use axum::{
    Json,
    http::{
        HeaderMap, HeaderName, HeaderValue, StatusCode,
        header::{AUTHORIZATION, CACHE_CONTROL, PRAGMA, WWW_AUTHENTICATE},
    },
    response::{IntoResponse, Response},
};

const MAX_BEARER_TOKEN_BYTES: usize = 512;
const LITELLM_KEY_PREFIX: &str = "sk-";
const MISSING_CHALLENGE: &str = "Bearer realm=\"litellm\"";
const INVALID_CHALLENGE: &str =
    "Bearer realm=\"litellm\", error=\"invalid_token\", error_description=\"A LiteLLM virtual key is required\"";

/// A non-secret reason for rejecting an inbound LLM credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CredentialRejection {
    Missing,
    Ambiguous,
    InvalidScheme,
    InvalidShape,
}

impl CredentialRejection {
    /// Stable reason code suitable for audit and security-event records.
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::Missing => "authorization_header_missing",
            Self::Ambiguous => "authorization_header_ambiguous",
            Self::InvalidScheme => "authorization_scheme_invalid",
            Self::InvalidShape => "credential_shape_invalid",
        }
    }

    const fn challenge(self) -> &'static str {
        match self {
            Self::Missing => MISSING_CHALLENGE,
            Self::Ambiguous | Self::InvalidScheme | Self::InvalidShape => INVALID_CHALLENGE,
        }
    }
}

/// Validate that exactly one RFC 6750 Bearer credential has the bounded lexical
/// shape used by LiteLLM virtual keys. This deliberately does not authenticate
/// the key; LiteLLM remains authoritative for revocation, team, budget, scope,
/// and key existence.
pub(crate) fn validate_litellm_virtual_key(
    headers: &HeaderMap,
) -> Result<(), CredentialRejection> {
    let mut values = headers.get_all(AUTHORIZATION).iter();
    let value = values.next().ok_or(CredentialRejection::Missing)?;
    if values.next().is_some() {
        return Err(CredentialRejection::Ambiguous);
    }
    let value = value
        .to_str()
        .map_err(|_| CredentialRejection::InvalidShape)?;
    let scheme_end = value
        .find(' ')
        .ok_or(CredentialRejection::InvalidScheme)?;
    let scheme = &value[..scheme_end];
    if !scheme.eq_ignore_ascii_case("Bearer") {
        return Err(CredentialRejection::InvalidScheme);
    }
    let after_scheme = &value[scheme_end..];
    let token = after_scheme.trim_start_matches(' ');
    if token.len() == after_scheme.len() || !valid_virtual_key_shape(token) {
        return Err(CredentialRejection::InvalidShape);
    }
    Ok(())
}

fn valid_virtual_key_shape(token: &str) -> bool {
    if token.len() <= LITELLM_KEY_PREFIX.len()
        || token.len() > MAX_BEARER_TOKEN_BYTES
        || !token.starts_with(LITELLM_KEY_PREFIX)
    {
        return false;
    }
    let mut padding_started = false;
    for byte in token.bytes() {
        if byte == b'=' {
            padding_started = true;
            continue;
        }
        if padding_started || !is_b64_token_byte(byte) {
            return false;
        }
    }
    true
}

const fn is_b64_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'+' | b'/')
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
        HeaderValue::from_static(rejection.challenge()),
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
/// Cookies, proxy headers, host routing, transfer framing, and forwarding-chain
/// headers are intentionally not copied.
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
            | "baggage"
    ) || name.as_str().starts_with("x-litellm-")
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
    use axum::http::header::COOKIE;

    fn headers(values: &[&str]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for value in values {
            headers.append(
                AUTHORIZATION,
                HeaderValue::from_str(value).expect("valid test header"),
            );
        }
        headers
    }

    #[test]
    fn accepts_bounded_litellm_bearer_shapes() {
        for value in [
            "Bearer sk-a",
            "bearer sk-team_123.ABC-~/+=",
            "BEARER   sk-virtual-key+pool/01==",
        ] {
            assert_eq!(validate_litellm_virtual_key(&headers(&[value])), Ok(()));
        }
    }

    #[test]
    fn rejects_missing_duplicate_scheme_and_shape_failures() {
        assert_eq!(
            validate_litellm_virtual_key(&HeaderMap::new()),
            Err(CredentialRejection::Missing)
        );
        assert_eq!(
            validate_litellm_virtual_key(&headers(&["Bearer sk-a", "Bearer sk-b"])),
            Err(CredentialRejection::Ambiguous)
        );
        for value in ["Basic c2stYQ==", "Bearersk-a", "Bearer\tsk-a"] {
            assert_eq!(
                validate_litellm_virtual_key(&headers(&[value])),
                Err(CredentialRejection::InvalidScheme)
            );
        }
        for value in [
            "Bearer 061012345318",
            "Bearer sk-",
            "Bearer sk-a b",
            "Bearer sk-a=tail",
            "Bearer sk-a?bad",
            "Bearer sk-a\t",
        ] {
            assert_eq!(
                validate_litellm_virtual_key(&headers(&[value])),
                Err(CredentialRejection::InvalidShape),
                "unexpected result for {value:?}"
            );
        }
        let oversized = format!("Bearer sk-{}", "a".repeat(MAX_BEARER_TOKEN_BYTES));
        assert_eq!(
            validate_litellm_virtual_key(&headers(&[&oversized])),
            Err(CredentialRejection::InvalidShape)
        );
    }

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
        source.insert(AUTHORIZATION, HeaderValue::from_static("Bearer sk-secret"));
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
