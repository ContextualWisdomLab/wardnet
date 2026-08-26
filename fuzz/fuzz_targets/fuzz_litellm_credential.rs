#![no_main]

use arbitrary::Arbitrary;
use axum::http::{HeaderMap, HeaderValue, header::AUTHORIZATION};
use libfuzzer_sys::fuzz_target;

#[path = "../../src/litellm_credential.rs"]
mod litellm_credential;

use litellm_credential::{
    CredentialRejection, MAX_AUTHORIZATION_HEADER_BYTES, validate_litellm_virtual_key,
};

#[derive(Arbitrary, Debug)]
struct HeaderInput {
    first: Vec<u8>,
    second: Option<Vec<u8>>,
}

fn append_if_valid(headers: &mut HeaderMap, raw: &[u8]) {
    if let Ok(value) = HeaderValue::from_bytes(raw) {
        headers.append(AUTHORIZATION, value);
    }
}

fuzz_target!(|input: HeaderInput| {
    let mut headers = HeaderMap::new();
    append_if_valid(&mut headers, &input.first);
    if let Some(second) = input.second.as_deref() {
        append_if_valid(&mut headers, second);
    }

    let count = headers.get_all(AUTHORIZATION).iter().count();
    let result = validate_litellm_virtual_key(&headers);
    for padding_only in ["Bearer sk-=", "Bearer sk-===="] {
        let mut invariant_headers = HeaderMap::new();
        invariant_headers.insert(AUTHORIZATION, HeaderValue::from_static(padding_only));
        assert_eq!(
            validate_litellm_virtual_key(&invariant_headers),
            Err(CredentialRejection::InvalidShape)
        );
    }
    if count > 1 {
        assert_eq!(result, Err(CredentialRejection::Ambiguous));
    }
    if result.is_ok() {
        let value = headers[AUTHORIZATION]
            .to_str()
            .expect("accepted credential is ASCII");
        assert!(value.len() <= MAX_AUTHORIZATION_HEADER_BYTES);
        assert!(value[..6].eq_ignore_ascii_case("Bearer"));
        assert!(value[6..].trim_start_matches(' ').starts_with("sk-"));
    }
});
