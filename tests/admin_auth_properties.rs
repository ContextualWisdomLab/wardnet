//! Stable property coverage for Wardnet's administrator credential boundary.
//!
//! These tests complement the parser libFuzzer target with the two behaviors
//! that only the application boundary can prove: credential-file values remain
//! strict JSON strings, and a header-authenticated principal reaches the same
//! write authorization encoded by `ADMIN_TOKENS`.

use axum::{
    body::Body,
    http::{header::CONTENT_TYPE, Method, Request, StatusCode},
};
use proptest::prelude::*;
use serde_json::Value;
use std::sync::atomic::{AtomicU64, Ordering};
use tower::ServiceExt;
use waf_ids_ai_soc::{
    build_app, parse_admin_tokens_strict, AppState, CredentialRegistry, CRED_ADMIN_TOKEN,
    CRED_ADMIN_TOKENS,
};

static NEXT_CREDENTIAL_FILE_ID: AtomicU64 = AtomicU64::new(1);

fn bootstrap_from_json_value(key: &str, value: Value) -> Result<CredentialRegistry, String> {
    let mut payload = serde_json::Map::new();
    payload.insert(key.to_string(), value);

    let id = NEXT_CREDENTIAL_FILE_ID.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "wardnet-admin-auth-property-{}-{id}.json",
        std::process::id()
    ));
    std::fs::write(&path, Value::Object(payload).to_string())
        .expect("property fixture must be writable");
    let result = CredentialRegistry::bootstrap_secrets(Some(&path), None, None);
    let _ = std::fs::remove_file(path);
    result
}

async fn create_route_status(app: axum::Router, presented_token: Option<&str>) -> StatusCode {
    let body = serde_json::json!({
        "id": "auth-property-route",
        "path_prefix": "/auth-property",
        "upstream": "mock://auth-property",
        "mode": "monitor",
        "enabled": true,
        "block_threshold": null
    })
    .to_string();

    let mut builder = Request::builder()
        .method(Method::POST)
        .uri("/api/routes")
        .header(CONTENT_TYPE, "application/json");
    if let Some(token) = presented_token {
        builder = builder.header("X-Admin-Token", token);
    }

    app.oneshot(builder.body(Body::from(body)).expect("valid request"))
        .await
        .expect("router must answer")
        .status()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    #[test]
    fn credentials_file_rejects_null_whitespace_and_non_string_admin_values(
        key_is_list in any::<bool>(),
        value in prop_oneof![
            Just(Value::Null),
            "[ \t]{1,8}".prop_map(Value::String),
            any::<bool>().prop_map(Value::Bool),
            any::<i64>().prop_map(|number| Value::Number(number.into())),
            proptest::collection::vec(any::<u8>(), 0..8).prop_map(|items| {
                Value::Array(
                    items
                        .into_iter()
                        .map(|number| Value::Number(number.into()))
                        .collect(),
                )
            }),
            Just(serde_json::json!({"nested": "credential"})),
        ],
    ) {
        let key = if key_is_list {
            CRED_ADMIN_TOKENS
        } else {
            CRED_ADMIN_TOKEN
        };
        let error = bootstrap_from_json_value(key, value).unwrap_err();
        prop_assert!(
            error.contains("must not be blank or null")
                || error.contains("must be a non-empty JSON string"),
            "unexpected credential error: {error}"
        );
    }

    #[test]
    fn header_authentication_preserves_rbac_write_semantics(
        writer_token in "[A-Za-z0-9._~-]{1,24}",
        actor in "[A-Za-z0-9._~-]{1,24}",
    ) {
        let reader_token = format!("{writer_token}-readonly");
        let wrong_token = format!("{writer_token}-wrong");
        let configured = format!(
            "{writer_token}:{actor}:operator,{reader_token}:{actor}:readonly"
        );
        let principals = parse_admin_tokens_strict(&configured)
            .expect("generated admin-token configuration must be valid");
        prop_assert!(principals.get(&writer_token).is_some_and(|principal| principal.can_write));
        prop_assert!(principals.get(&reader_token).is_some_and(|principal| !principal.can_write));

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime");
        runtime.block_on(async {
            let app = build_app(AppState::seeded(None).with_admin_tokens(principals));

            let unauthenticated = create_route_status(app.clone(), None).await;
            let wrong = create_route_status(app.clone(), Some(&wrong_token)).await;
            let readonly = create_route_status(app.clone(), Some(&reader_token)).await;
            let writer = create_route_status(app, Some(&writer_token)).await;

            prop_assert_eq!(unauthenticated, StatusCode::UNAUTHORIZED);
            prop_assert_eq!(wrong, StatusCode::UNAUTHORIZED);
            prop_assert_eq!(readonly, StatusCode::FORBIDDEN);
            prop_assert_eq!(writer, StatusCode::CREATED);
            Ok(())
        })?;
    }
}
