use axum::http::{HeaderMap, header::AUTHORIZATION};

pub(crate) const MAX_BEARER_TOKEN_BYTES: usize = 512;
const BEARER_SCHEME: &str = "Bearer";
const MAX_SCHEME_SEPARATOR_BYTES: usize = 8;
pub(crate) const MAX_AUTHORIZATION_HEADER_BYTES: usize =
    BEARER_SCHEME.len() + MAX_SCHEME_SEPARATOR_BYTES + MAX_BEARER_TOKEN_BYTES;
const LITELLM_KEY_PREFIX: &str = "sk-";

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
}

/// Validate that exactly one RFC 6750 Bearer credential has the bounded lexical
/// shape used by LiteLLM virtual keys.
///
/// This is a credential-class guard, not authentication. LiteLLM remains
/// authoritative for key existence, revocation, team, budget, model scope, and
/// other entitlements.
pub(crate) fn validate_litellm_virtual_key(headers: &HeaderMap) -> Result<(), CredentialRejection> {
    let mut values = headers.get_all(AUTHORIZATION).iter();
    let value = values.next().ok_or(CredentialRejection::Missing)?;
    if values.next().is_some() {
        return Err(CredentialRejection::Ambiguous);
    }

    // Bound all subsequent scans, including HeaderValue::to_str, before parsing
    // the untrusted value. The separator itself is intentionally bounded too.
    if value.as_bytes().len() > MAX_AUTHORIZATION_HEADER_BYTES {
        return Err(CredentialRejection::InvalidShape);
    }
    let value = value
        .to_str()
        .map_err(|_| CredentialRejection::InvalidShape)?;
    if value.len() <= BEARER_SCHEME.len() {
        return Err(CredentialRejection::InvalidScheme);
    }

    let (scheme, after_scheme) = value.split_at(BEARER_SCHEME.len());
    if !scheme.eq_ignore_ascii_case(BEARER_SCHEME) {
        return Err(CredentialRejection::InvalidScheme);
    }

    let mut separator_len = 0usize;
    for byte in after_scheme.bytes() {
        if byte != b' ' {
            break;
        }
        separator_len += 1;
        if separator_len > MAX_SCHEME_SEPARATOR_BYTES {
            return Err(CredentialRejection::InvalidShape);
        }
    }
    if separator_len == 0 {
        return Err(CredentialRejection::InvalidScheme);
    }

    let token = &after_scheme[separator_len..];
    if !valid_virtual_key_shape(token) {
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
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'+' | b'/')
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

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

        let token = format!("sk-{}", "a".repeat(MAX_BEARER_TOKEN_BYTES - 3));
        assert_eq!(token.len(), MAX_BEARER_TOKEN_BYTES);
        let header = format!("Bearer{}{}", " ".repeat(MAX_SCHEME_SEPARATOR_BYTES), token);
        assert_eq!(header.len(), MAX_AUTHORIZATION_HEADER_BYTES);
        assert_eq!(validate_litellm_virtual_key(&headers(&[&header])), Ok(()));
    }

    #[test]
    fn rejects_missing_duplicate_and_wrong_scheme() {
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
    }

    #[test]
    fn rejects_shape_padding_separator_and_non_ascii_failures() {
        for value in [
            "Bearer 01000000000",
            "Bearer sk-",
            "Bearer sk-a b",
            "Bearer sk-a=tail",
            "Bearer sk-a?bad",
            "Bearer sk-a\t",
            "Bearer         sk-a",
        ] {
            assert_eq!(
                validate_litellm_virtual_key(&headers(&[value])),
                Err(CredentialRejection::InvalidShape),
                "unexpected result for {value:?}"
            );
        }

        let token_too_long = format!("Bearer sk-{}", "a".repeat(MAX_BEARER_TOKEN_BYTES - 2));
        assert_eq!(
            validate_litellm_virtual_key(&headers(&[&token_too_long])),
            Err(CredentialRejection::InvalidShape)
        );

        let mut non_ascii_headers = HeaderMap::new();
        non_ascii_headers.append(
            AUTHORIZATION,
            HeaderValue::from_bytes(b"Bearer sk-a\x80").expect("valid opaque header bytes"),
        );
        assert_eq!(
            validate_litellm_virtual_key(&non_ascii_headers),
            Err(CredentialRejection::InvalidShape)
        );
    }

    #[test]
    fn rejects_oversized_values_before_delimiter_scans() {
        let no_space = "X".repeat(MAX_AUTHORIZATION_HEADER_BYTES + 1);
        assert_eq!(
            validate_litellm_virtual_key(&headers(&[&no_space])),
            Err(CredentialRejection::InvalidShape)
        );

        let excessive_spaces = format!("Bearer{}sk-a", " ".repeat(MAX_AUTHORIZATION_HEADER_BYTES));
        assert_eq!(
            validate_litellm_virtual_key(&headers(&[&excessive_spaces])),
            Err(CredentialRejection::InvalidShape)
        );
    }
}
