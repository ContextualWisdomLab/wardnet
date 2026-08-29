use std::sync::Arc;

use axum::{
    body::{Body, to_bytes},
    http::{HeaderValue, Request, StatusCode, header::CONTENT_TYPE},
};
use serde::de::DeserializeOwned;
use tower::ServiceExt;
use wardnet_agent_artifact_admission::{
    AdmissionDecision, AdmissionPolicy, AdmissionState, ApprovedArtifact, ApprovedManifest,
    AuditError, AuditRecord, AuditSink, DecisionKind, InstallIntent, MemoryAuditSink, ReasonCode,
    build_app,
};

const ADMIN_TOKEN: &str = "0123456789abcdef0123456789abcdef";

fn digest(byte: char) -> String {
    std::iter::repeat_n(byte, 64).collect()
}

fn approved_policy() -> AdmissionPolicy {
    AdmissionPolicy {
        policy_id: "enterprise-default".to_string(),
        policy_revision: "2026-08-29.2".to_string(),
        allowed_executables: vec!["npm".to_string()],
        approved_manifests: vec![ApprovedManifest {
            workspace_id: "ContextualWisdomLab/wardnet".to_string(),
            sha256: digest('a'),
        }],
        approved_artifacts: vec![ApprovedArtifact {
            ecosystem: "npm".to_string(),
            name: "@unowned/example".to_string(),
            version: "1.2.3".to_string(),
            registry_url: "https://registry.npmjs.org".to_string(),
            owner: "Unowned".to_string(),
            sha256: digest('c'),
            artifact_argument: "@unowned/example@1.2.3".to_string(),
        }],
    }
}

fn approved_intent() -> InstallIntent {
    InstallIntent::unowned_llms_package_for_test()
}

fn state(
    policy: AdmissionPolicy,
    sink: Arc<dyn AuditSink>,
    max_request_body_bytes: usize,
) -> AdmissionState {
    AdmissionState::new(
        policy,
        ADMIN_TOKEN.to_string(),
        sink,
        max_request_body_bytes,
    )
}

fn admission_request(body: Vec<u8>, token: Option<HeaderValue>) -> Request<Body> {
    let mut request = Request::builder()
        .method("POST")
        .uri("/v1/admissions")
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .expect("request must build");
    if let Some(token) = token {
        request.headers_mut().append("x-admin-token", token);
    }
    request
}

fn policy_request(token: Option<HeaderValue>) -> Request<Body> {
    let mut request = Request::builder()
        .method("GET")
        .uri("/v1/policy")
        .body(Body::empty())
        .expect("request must build");
    if let Some(token) = token {
        request.headers_mut().append("x-admin-token", token);
    }
    request
}

async fn decode_json<T: DeserializeOwned>(response: axum::response::Response) -> T {
    let bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("response body must be readable");
    serde_json::from_slice(&bytes).expect("response body must be JSON")
}

#[tokio::test]
async fn policy_endpoint_rejects_missing_duplicate_wrong_non_ascii_and_oversized_tokens() {
    let sink = Arc::new(MemoryAuditSink::default());
    let app = build_app(state(approved_policy(), sink, 64 * 1024));

    let mut cases = vec![
        policy_request(None),
        policy_request(Some(HeaderValue::from_static(
            "fedcba9876543210fedcba9876543210",
        ))),
        policy_request(Some(HeaderValue::from_static(
            "0123456789abcdef0123456789abcdefx",
        ))),
        policy_request(Some(HeaderValue::from_static(""))),
        policy_request(Some(
            HeaderValue::from_str(&"x".repeat(4097)).expect("oversized test header must build"),
        )),
    ];

    let non_ascii = vec![0x80; 32];
    cases.push(policy_request(Some(
        HeaderValue::from_bytes(&non_ascii).expect("obs-text test header must build"),
    )));

    let mut duplicate = policy_request(Some(HeaderValue::from_static(ADMIN_TOKEN)));
    duplicate
        .headers_mut()
        .append("x-admin-token", HeaderValue::from_static(ADMIN_TOKEN));
    cases.push(duplicate);

    for request in cases {
        let response = app
            .clone()
            .oneshot(request)
            .await
            .expect("router must answer");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    let response = app
        .oneshot(policy_request(Some(HeaderValue::from_static(ADMIN_TOKEN))))
        .await
        .expect("router must answer");
    assert_eq!(response.status(), StatusCode::OK);
    let returned: AdmissionPolicy = decode_json(response).await;
    assert_eq!(returned, approved_policy());
}

#[tokio::test]
async fn health_is_unauthenticated_and_exposes_only_policy_identity_and_counts() {
    let sink = Arc::new(MemoryAuditSink::default());
    let app = build_app(state(approved_policy(), sink, 64 * 1024));
    let request = Request::builder()
        .uri("/healthz")
        .body(Body::empty())
        .expect("request must build");

    let response = app.oneshot(request).await.expect("router must answer");

    assert_eq!(response.status(), StatusCode::OK);
    let body: serde_json::Value = decode_json(response).await;
    assert_eq!(body["status"], "ok");
    assert_eq!(body["policy_id"], "enterprise-default");
    assert_eq!(body["policy_revision"], "2026-08-29.2");
    assert_eq!(body["approved_manifest_count"], 1);
    assert_eq!(body["approved_artifact_count"], 1);
    assert!(body.get("admin_token").is_none());
}

#[tokio::test]
async fn candidate_allow_is_returned_only_after_audit_append() {
    let sink = Arc::new(MemoryAuditSink::default());
    let app = build_app(state(approved_policy(), sink.clone(), 64 * 1024));
    let body = serde_json::to_vec(&approved_intent()).expect("intent must serialize");

    let response = app
        .oneshot(admission_request(
            body,
            Some(HeaderValue::from_static(ADMIN_TOKEN)),
        ))
        .await
        .expect("router must answer");

    assert_eq!(response.status(), StatusCode::OK);
    let decision: AdmissionDecision = decode_json(response).await;
    assert_eq!(decision.decision, DecisionKind::Allow);
    let records = sink.records().expect("audit snapshot must succeed");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].decision, DecisionKind::Allow);
    assert_eq!(records[0].request_id, decision.request_id);
}

#[tokio::test]
async fn policy_block_is_a_durable_http_200_decision() {
    let sink = Arc::new(MemoryAuditSink::default());
    let app = build_app(state(
        AdmissionPolicy::deny_all_for_test(),
        sink.clone(),
        64 * 1024,
    ));
    let body = serde_json::to_vec(&approved_intent()).expect("intent must serialize");

    let response = app
        .oneshot(admission_request(
            body,
            Some(HeaderValue::from_static(ADMIN_TOKEN)),
        ))
        .await
        .expect("router must answer");

    assert_eq!(response.status(), StatusCode::OK);
    let decision: AdmissionDecision = decode_json(response).await;
    assert_eq!(decision.decision, DecisionKind::Block);
    assert!(
        decision
            .reason_codes
            .contains(&ReasonCode::ArtifactNotApproved)
    );
    let records = sink.records().expect("audit snapshot must succeed");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].decision, DecisionKind::Block);
}

#[tokio::test]
async fn malformed_authenticated_json_is_audited_before_bad_request() {
    let sink = Arc::new(MemoryAuditSink::default());
    let app = build_app(state(approved_policy(), sink.clone(), 64 * 1024));

    let response = app
        .oneshot(admission_request(
            br#"{"request_id":"unfinished""#.to_vec(),
            Some(HeaderValue::from_static(ADMIN_TOKEN)),
        ))
        .await
        .expect("router must answer");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let decision: AdmissionDecision = decode_json(response).await;
    assert_eq!(decision.decision, DecisionKind::Block);
    assert!(decision.reason_codes.contains(&ReasonCode::MalformedRequest));
    let records = sink.records().expect("audit snapshot must succeed");
    assert_eq!(records.len(), 1);
    assert!(records[0].request_id.starts_with("malformed:"));
    assert!(
        records[0]
            .reason_codes
            .contains(&ReasonCode::MalformedRequest)
    );
}

#[tokio::test]
async fn structurally_invalid_authenticated_intent_is_audited_and_returns_bad_request() {
    let sink = Arc::new(MemoryAuditSink::default());
    let app = build_app(state(approved_policy(), sink.clone(), 64 * 1024));
    let mut intent = approved_intent();
    intent.operation = "execute".to_string();

    let response = app
        .oneshot(admission_request(
            serde_json::to_vec(&intent).expect("intent must serialize"),
            Some(HeaderValue::from_static(ADMIN_TOKEN)),
        ))
        .await
        .expect("router must answer");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let decision: AdmissionDecision = decode_json(response).await;
    assert_eq!(decision.decision, DecisionKind::Block);
    assert!(decision.reason_codes.contains(&ReasonCode::InvalidOperation));
    let records = sink.records().expect("audit snapshot must succeed");
    assert_eq!(records.len(), 1);
    assert!(
        records[0]
            .reason_codes
            .contains(&ReasonCode::InvalidOperation)
    );
}

struct FailingAuditSink;

impl AuditSink for FailingAuditSink {
    fn append(&self, _record: &AuditRecord) -> Result<(), AuditError> {
        Err(AuditError::StorageUnavailable)
    }
}

#[tokio::test]
async fn audit_outage_converts_candidate_allow_and_block_to_service_unavailable() {
    for policy in [approved_policy(), AdmissionPolicy::deny_all_for_test()] {
        let app = build_app(state(policy, Arc::new(FailingAuditSink), 64 * 1024));
        let body = serde_json::to_vec(&approved_intent()).expect("intent must serialize");

        let response = app
            .oneshot(admission_request(
                body,
                Some(HeaderValue::from_static(ADMIN_TOKEN)),
            ))
            .await
            .expect("router must answer");

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let decision: AdmissionDecision = decode_json(response).await;
        assert_eq!(decision.decision, DecisionKind::Block);
        assert_eq!(decision.reason_codes, vec![ReasonCode::AuditUnavailable]);
    }
}

#[tokio::test]
async fn configured_body_limit_returns_payload_too_large_without_an_audit_record() {
    let sink = Arc::new(MemoryAuditSink::default());
    let app = build_app(state(approved_policy(), sink.clone(), 32));

    let response = app
        .oneshot(admission_request(
            vec![b'x'; 128],
            Some(HeaderValue::from_static(ADMIN_TOKEN)),
        ))
        .await
        .expect("router must answer");

    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert!(
        sink.records()
            .expect("audit snapshot must succeed")
            .is_empty()
    );
}
