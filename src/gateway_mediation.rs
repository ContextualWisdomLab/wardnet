use axum::http::{HeaderMap, HeaderName};
use std::collections::HashSet;

const APP_METADATA_HEADER: &str = "x-wardnet-app-meta";
const APP_METADATA_MAX_BYTES: usize = 16_384;
const REQUEST_ALLOWED: &[&str] = &[
    "content-type",
    "content-encoding",
    "accept",
    APP_METADATA_HEADER,
];
const RESPONSE_ALLOWED: &[&str] = &[
    "content-type",
    "content-encoding",
    APP_METADATA_HEADER,
    "location",
    "retry-after",
    "www-authenticate",
];

pub(crate) fn admit_request_headers(source: &HeaderMap) -> Result<HeaderMap, String> {
    reject_duplicate(source, "x-admin-token")?;
    reject_duplicate(source, "content-type")?;
    reject_oversized_app_metadata(source)?;
    admit_allowlisted(source, REQUEST_ALLOWED)
}

pub(crate) fn admit_response_headers(source: &HeaderMap) -> Result<HeaderMap, String> {
    reject_duplicate(source, "content-type")?;
    reject_duplicate(source, "location")?;
    reject_duplicate(source, "retry-after")?;
    reject_oversized_app_metadata(source)?;
    admit_allowlisted(source, RESPONSE_ALLOWED)
}

fn reject_duplicate(source: &HeaderMap, name: &'static str) -> Result<(), String> {
    if source.get_all(name).iter().take(2).count() > 1 {
        return Err(format!("gateway header {name} must not be duplicated"));
    }
    Ok(())
}

fn reject_oversized_app_metadata(source: &HeaderMap) -> Result<(), String> {
    let total = source
        .get_all(APP_METADATA_HEADER)
        .iter()
        .fold(0usize, |size, value| {
            size.saturating_add(value.as_bytes().len())
        });
    if total > APP_METADATA_MAX_BYTES {
        return Err(format!(
            "gateway header {APP_METADATA_HEADER} exceeds {APP_METADATA_MAX_BYTES} bytes"
        ));
    }
    Ok(())
}

fn connection_nominations(source: &HeaderMap) -> Result<HashSet<HeaderName>, String> {
    let mut nominated = HashSet::new();
    for value in source.get_all("connection").iter() {
        let raw = value
            .to_str()
            .map_err(|_| "gateway Connection header must be visible ASCII".to_string())?;
        for token in raw
            .split(',')
            .map(str::trim)
            .filter(|token| !token.is_empty())
        {
            let name = HeaderName::from_bytes(token.as_bytes())
                .map_err(|_| format!("gateway Connection nomination {token:?} is invalid"))?;
            nominated.insert(name);
        }
    }
    Ok(nominated)
}

fn admit_allowlisted(source: &HeaderMap, allowed: &[&'static str]) -> Result<HeaderMap, String> {
    let nominated = connection_nominations(source)?;
    let mut admitted = HeaderMap::new();
    for &name in allowed {
        let header_name = HeaderName::from_static(name);
        if nominated.contains(&header_name) {
            continue;
        }
        for value in source.get_all(name).iter() {
            admitted.append(header_name.clone(), value.clone());
        }
    }
    Ok(admitted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn request_policy_preserves_only_bounded_allowlist_with_multiplicity() {
        let mut source = HeaderMap::new();
        source.append("content-type", HeaderValue::from_static("application/json"));
        source.append("content-encoding", HeaderValue::from_static("gzip"));
        source.append("content-encoding", HeaderValue::from_static("br"));
        source.append("accept", HeaderValue::from_static("application/json"));
        source.append(APP_METADATA_HEADER, HeaderValue::from_static("a"));
        source.append(APP_METADATA_HEADER, HeaderValue::from_static("b"));
        source.append("authorization", HeaderValue::from_static("Bearer secret"));

        let admitted = admit_request_headers(&source).unwrap();
        assert_eq!(admitted.get("content-type").unwrap(), "application/json");
        assert_eq!(
            admitted
                .get_all("content-encoding")
                .iter()
                .map(|value| value.to_str().unwrap())
                .collect::<Vec<_>>(),
            ["gzip", "br"]
        );
        assert_eq!(admitted.get("accept").unwrap(), "application/json");
        assert_eq!(admitted.get_all(APP_METADATA_HEADER).iter().count(), 2);
        assert!(admitted.get("authorization").is_none());
    }

    #[test]
    fn duplicate_and_oversized_request_authority_fail_closed() {
        let mut duplicate_admin = HeaderMap::new();
        duplicate_admin.append("x-admin-token", HeaderValue::from_static("a"));
        duplicate_admin.append("x-admin-token", HeaderValue::from_static("b"));
        assert!(admit_request_headers(&duplicate_admin).is_err());

        let mut duplicate_type = HeaderMap::new();
        duplicate_type.append("content-type", HeaderValue::from_static("text/plain"));
        duplicate_type.append("content-type", HeaderValue::from_static("application/json"));
        assert!(admit_request_headers(&duplicate_type).is_err());

        let mut oversized = HeaderMap::new();
        oversized.insert(
            APP_METADATA_HEADER,
            HeaderValue::from_str(&"x".repeat(APP_METADATA_MAX_BYTES + 1)).unwrap(),
        );
        assert!(admit_request_headers(&oversized).is_err());
    }

    #[test]
    fn connection_nominations_remove_otherwise_allowed_fields() {
        let mut source = HeaderMap::new();
        source.append(APP_METADATA_HEADER, HeaderValue::from_static("keep-out"));
        source.append("content-encoding", HeaderValue::from_static("gzip"));
        source.append(
            "connection",
            HeaderValue::from_static("x-wardnet-app-meta, content-encoding"),
        );
        let admitted = admit_request_headers(&source).unwrap();
        assert!(admitted.get(APP_METADATA_HEADER).is_none());
        assert!(admitted.get("content-encoding").is_none());

        let mut malformed = HeaderMap::new();
        malformed.append("connection", HeaderValue::from_bytes(&[0xff]).unwrap());
        assert!(admit_request_headers(&malformed).is_err());

        let mut invalid_nomination = HeaderMap::new();
        invalid_nomination.append("connection", HeaderValue::from_static("bad name"));
        assert!(admit_request_headers(&invalid_nomination).is_err());
    }

    #[test]
    fn response_policy_preserves_representation_metadata_and_strips_authority() {
        let mut source = HeaderMap::new();
        source.append("content-type", HeaderValue::from_static("application/json"));
        source.append("content-encoding", HeaderValue::from_static("gzip"));
        source.append("content-encoding", HeaderValue::from_static("br"));
        source.append(APP_METADATA_HEADER, HeaderValue::from_static("a"));
        source.append(APP_METADATA_HEADER, HeaderValue::from_static("b"));
        source.append("location", HeaderValue::from_static("/v1/items/42"));
        source.append("retry-after", HeaderValue::from_static("5"));
        source.append(
            "www-authenticate",
            HeaderValue::from_static("Bearer realm=\"buyer\""),
        );
        source.append("set-cookie", HeaderValue::from_static("secret=1"));
        source.append("connection", HeaderValue::from_static(APP_METADATA_HEADER));

        let admitted = admit_response_headers(&source).unwrap();
        assert_eq!(admitted.get("content-type").unwrap(), "application/json");
        assert_eq!(
            admitted
                .get_all("content-encoding")
                .iter()
                .map(|value| value.to_str().unwrap())
                .collect::<Vec<_>>(),
            ["gzip", "br"]
        );
        assert!(admitted.get(APP_METADATA_HEADER).is_none());
        assert_eq!(admitted.get("location").unwrap(), "/v1/items/42");
        assert_eq!(admitted.get("retry-after").unwrap(), "5");
        assert!(admitted.get("www-authenticate").is_some());
        assert!(admitted.get("set-cookie").is_none());
    }

    #[test]
    fn response_policy_rejects_duplicate_singletons_and_oversized_metadata() {
        for name in ["content-type", "location", "retry-after"] {
            let mut duplicate = HeaderMap::new();
            duplicate.append(name, HeaderValue::from_static("first"));
            duplicate.append(name, HeaderValue::from_static("second"));
            assert!(
                admit_response_headers(&duplicate).is_err(),
                "duplicate {name} must fail closed"
            );
        }

        let mut oversized = HeaderMap::new();
        oversized.insert(
            APP_METADATA_HEADER,
            HeaderValue::from_str(&"x".repeat(APP_METADATA_MAX_BYTES + 1)).unwrap(),
        );
        assert!(admit_response_headers(&oversized).is_err());
    }
}
