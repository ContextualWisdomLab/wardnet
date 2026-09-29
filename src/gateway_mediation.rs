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
    // SSE relays need no-cache so the edge proxy does not buffer the stream.
    "cache-control",
    "www-authenticate",
];

pub(crate) fn admit_request_headers(source: &HeaderMap) -> Result<HeaderMap, String> {
    reject_duplicate(source, "x-admin-token")?;
    reject_duplicate(source, "content-type")?;
    reject_oversized_app_metadata(source)?;
    admit_allowlisted(source, REQUEST_ALLOWED)
}

/// The fixed request allowlist plus the route's extra forwarded headers.
/// An extra header must not repeat, and a `Connection` nomination still drops it.
pub(crate) fn admit_route_request_headers(
    source: &HeaderMap,
    extra: &[String],
) -> Result<HeaderMap, String> {
    let mut admitted = admit_request_headers(source)?;
    let nominated = connection_nominations(source)?;
    for name in extra {
        let header_name = HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| format!("gateway route header {name:?} is invalid"))?;
        if nominated.contains(&header_name) {
            // Dropping a forwarded credential would turn a valid request into
            // an upstream 401 and a strike against the caller.
            return Err(format!(
                "gateway header {name} must not be nominated in Connection"
            ));
        }
        let mut values = source.get_all(&header_name).iter();
        if let Some(value) = values.next() {
            if values.next().is_some() {
                return Err(format!("gateway header {name} must not be duplicated"));
            }
            admitted.insert(header_name, value.clone());
        }
    }
    Ok(admitted)
}

const CREDENTIAL_MAX_BYTES: usize = 512;

/// Checks that the caller sent one well-formed credential: `Authorization:
/// Bearer <token>` or `x-litellm-api-key: [Bearer ]<token>`. It does not decide
/// whether the credential is valid; the upstream does.
#[cfg(test)]
pub(crate) fn admit_credential(
    source: &HeaderMap,
    prefix: Option<&str>,
) -> Result<(), &'static str> {
    admit_credential_in(source, prefix, &[])
}

const DEFAULT_CREDENTIAL_HEADERS: &[&str] = &["authorization", "x-litellm-api-key"];

/// One well-formed credential in exactly one of the route's credential
/// headers. `authorization` needs the Bearer scheme; the others (for example
/// Anthropic's `x-api-key` or Azure's `api-key`) carry the bare token.
pub(crate) fn admit_credential_in(
    source: &HeaderMap,
    prefix: Option<&str>,
    names: &[String],
) -> Result<(), &'static str> {
    let names: Vec<&str> = if names.is_empty() {
        DEFAULT_CREDENTIAL_HEADERS.to_vec()
    } else {
        names.iter().map(String::as_str).collect()
    };
    let present: Vec<&str> = names
        .iter()
        .copied()
        .filter(|name| source.contains_key(*name))
        .collect();
    match present.as_slice() {
        [] => return Err("missing credential"),
        [_] => {}
        _ => return Err("conflicting credential headers"),
    }
    let name = present[0];
    let mut values = source.get_all(name).iter();
    let value = values.next().ok_or("missing credential")?;
    if values.next().is_some() {
        return Err("duplicate credential header");
    }
    let raw = value.to_str().map_err(|_| "malformed credential")?;
    let token = match raw.split_once(' ') {
        Some((scheme, token)) if scheme.eq_ignore_ascii_case("bearer") => token,
        Some(_) => return Err("unsupported credential scheme"),
        None if name == "authorization" => return Err("unsupported credential scheme"),
        None => raw,
    };
    let well_formed = !token.is_empty()
        && token.len() <= CREDENTIAL_MAX_BYTES
        && token.bytes().all(|b| (0x21..=0x7e).contains(&b))
        && prefix.is_none_or(|prefix| token.len() > prefix.len() && token.starts_with(prefix));
    if well_formed {
        Ok(())
    } else {
        Err("malformed credential")
    }
}

/// Hop-by-hop and framing headers (RFC 9110 section 7.6.1), plus Wardnet's
/// own management credential. Everything else is end-to-end.
const NOT_END_TO_END: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-connection",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "host",
    "content-length",
    "x-admin-token",
];

/// Every end-to-end header, with multiplicity, minus hop-by-hop, framing,
/// Connection nominations and the Wardnet admin token.
pub(crate) fn admit_transparent(source: &HeaderMap) -> Result<HeaderMap, String> {
    reject_duplicate(source, "content-type")?;
    let nominated = connection_nominations(source)?;
    let mut admitted = HeaderMap::new();
    for (name, value) in source.iter() {
        if NOT_END_TO_END.contains(&name.as_str()) || nominated.contains(name) {
            continue;
        }
        admitted.append(name.clone(), value.clone());
    }
    Ok(admitted)
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

    fn headers(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.append(*name, HeaderValue::from_static(value));
        }
        map
    }

    #[test]
    fn route_headers_forward_credentials_only_when_configured() {
        let source = headers(&[("authorization", "Bearer sk-1"), ("cookie", "a=b")]);
        assert!(
            admit_route_request_headers(&source, &[])
                .unwrap()
                .get("authorization")
                .is_none()
        );
        let admitted =
            admit_route_request_headers(&source, &["authorization".to_string()]).unwrap();
        assert_eq!(admitted.get("authorization").unwrap(), "Bearer sk-1");
        assert!(admitted.get("cookie").is_none());
        let duplicated = headers(&[("authorization", "Bearer a"), ("authorization", "Bearer b")]);
        assert!(admit_route_request_headers(&duplicated, &["authorization".to_string()]).is_err());
        let nominated = headers(&[
            ("authorization", "Bearer a"),
            ("connection", "authorization"),
        ]);
        assert!(admit_route_request_headers(&nominated, &["authorization".to_string()]).is_err());
    }

    #[test]
    fn credential_headers_are_route_configurable() {
        let names = vec![
            "authorization".to_string(),
            "x-api-key".to_string(),
            "api-key".to_string(),
        ];
        assert!(
            admit_credential_in(&headers(&[("x-api-key", "sk-abc")]), Some("sk-"), &names).is_ok()
        );
        assert!(
            admit_credential_in(
                &headers(&[("api-key", "Bearer sk-abc")]),
                Some("sk-"),
                &names
            )
            .is_ok()
        );
        assert_eq!(
            admit_credential_in(
                &headers(&[("x-api-key", "sk-a"), ("api-key", "sk-b")]),
                None,
                &names
            ),
            Err("conflicting credential headers")
        );
        assert_eq!(
            admit_credential_in(&headers(&[("x-litellm-api-key", "sk-a")]), None, &names),
            Err("missing credential"),
            "only the route's headers count"
        );
    }

    #[test]
    fn transparent_policy_drops_only_hop_by_hop_and_admin_headers() {
        let source = headers(&[
            ("mcp-session-id", "s"),
            ("x-litellm-tags", "t"),
            ("connection", "x-custom-hop"),
            ("x-custom-hop", "gone"),
            ("transfer-encoding", "chunked"),
            ("x-admin-token", "secret"),
            ("host", "example"),
        ]);
        let admitted = admit_transparent(&source).unwrap();
        assert!(admitted.contains_key("mcp-session-id") && admitted.contains_key("x-litellm-tags"));
        for gone in [
            "connection",
            "x-custom-hop",
            "transfer-encoding",
            "x-admin-token",
            "host",
        ] {
            assert!(!admitted.contains_key(gone), "{gone} must not pass");
        }
    }

    #[test]
    fn credential_admission_requires_one_well_formed_token() {
        let prefix = Some("sk-");
        assert_eq!(
            admit_credential(&HeaderMap::new(), prefix),
            Err("missing credential")
        );
        for (name, value) in [
            ("authorization", "Bearer "),
            ("authorization", "Bearer ' OR 1=1--"),
            ("authorization", "Bearer {}"),
            ("authorization", "Bearer none"),
            ("x-litellm-api-key", "{}"),
            ("authorization", "Bearer sk-"),
        ] {
            let map = headers(&[(name, value)]);
            assert_eq!(
                admit_credential(&map, prefix),
                Err("malformed credential"),
                "{name}: {value}"
            );
        }
        assert_eq!(
            admit_credential(&headers(&[("authorization", "Basic abc")]), prefix),
            Err("unsupported credential scheme")
        );
        assert_eq!(
            admit_credential(&headers(&[("authorization", "sk-raw")]), prefix),
            Err("unsupported credential scheme")
        );
        assert_eq!(
            admit_credential(
                &headers(&[("authorization", "Bearer a"), ("authorization", "Bearer b")]),
                None
            ),
            Err("duplicate credential header")
        );
        assert_eq!(
            admit_credential(
                &headers(&[
                    ("authorization", "Bearer sk-a"),
                    ("x-litellm-api-key", "sk-b")
                ]),
                prefix
            ),
            Err("conflicting credential headers")
        );
        assert!(admit_credential(&headers(&[("authorization", "bearer sk-ok")]), prefix).is_ok());
        assert!(admit_credential(&headers(&[("x-litellm-api-key", "sk-ok")]), prefix).is_ok());
        assert!(
            admit_credential(&headers(&[("x-litellm-api-key", "Bearer sk-ok")]), prefix).is_ok()
        );
    }

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
