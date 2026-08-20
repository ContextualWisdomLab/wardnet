#[path = "../src/litellm_credential.rs"]
mod litellm_credential;

use axum::http::{HeaderMap, HeaderValue, header::AUTHORIZATION};
use litellm_credential::{
    CredentialRejection, MAX_AUTHORIZATION_HEADER_BYTES, validate_litellm_virtual_key,
};
use proptest::prelude::*;

fn single_header(raw: &[u8]) -> Option<HeaderMap> {
    let value = HeaderValue::from_bytes(raw).ok()?;
    let mut headers = HeaderMap::new();
    headers.append(AUTHORIZATION, value);
    Some(headers)
}

#[test]
fn rejection_reason_codes_are_stable_and_non_secret() {
    assert_eq!(
        CredentialRejection::Missing.code(),
        "authorization_header_missing"
    );
    assert_eq!(
        CredentialRejection::Ambiguous.code(),
        "authorization_header_ambiguous"
    );
    assert_eq!(
        CredentialRejection::InvalidScheme.code(),
        "authorization_scheme_invalid"
    );
    assert_eq!(
        CredentialRejection::InvalidShape.code(),
        "credential_shape_invalid"
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn arbitrary_header_bytes_never_panic(raw in prop::collection::vec(any::<u8>(), 0..2048)) {
        if let Some(headers) = single_header(&raw) {
            let result = validate_litellm_virtual_key(&headers);
            if result.is_ok() {
                let value = headers[AUTHORIZATION].to_str().expect("accepted value is ASCII");
                prop_assert!(value.len() <= MAX_AUTHORIZATION_HEADER_BYTES);
                prop_assert!(value[..6].eq_ignore_ascii_case("Bearer"));
                prop_assert!(value[6..].trim_start_matches(' ').starts_with("sk-"));
            }
        }
    }

    #[test]
    fn duplicate_values_are_always_ambiguous(
        first in "[ -~]{0,256}",
        second in "[ -~]{0,256}"
    ) {
        let mut headers = HeaderMap::new();
        headers.append(AUTHORIZATION, HeaderValue::from_str(&first).unwrap());
        headers.append(AUTHORIZATION, HeaderValue::from_str(&second).unwrap());
        prop_assert_eq!(
            validate_litellm_virtual_key(&headers),
            Err(CredentialRejection::Ambiguous)
        );
    }

    #[test]
    fn excessive_spaces_are_rejected(spaces in 9usize..128) {
        let raw = format!("Bearer{}sk-a", " ".repeat(spaces));
        let headers = single_header(raw.as_bytes()).unwrap();
        prop_assert_eq!(
            validate_litellm_virtual_key(&headers),
            Err(CredentialRejection::InvalidShape)
        );
    }

    #[test]
    fn padding_only_payloads_are_rejected(padding in 1usize..128) {
        let raw = format!("Bearer sk-{}", "=".repeat(padding));
        let headers = single_header(raw.as_bytes()).unwrap();
        prop_assert_eq!(
            validate_litellm_virtual_key(&headers),
            Err(CredentialRejection::InvalidShape)
        );
    }

    #[test]
    fn padding_followed_by_data_is_rejected(
        left in "[A-Za-z0-9._~+/-]{1,48}",
        right in "[A-Za-z0-9._~+/-]{1,48}"
    ) {
        let raw = format!("Bearer sk-{left}={right}");
        let headers = single_header(raw.as_bytes()).unwrap();
        prop_assert_eq!(
            validate_litellm_virtual_key(&headers),
            Err(CredentialRejection::InvalidShape)
        );
    }
}
