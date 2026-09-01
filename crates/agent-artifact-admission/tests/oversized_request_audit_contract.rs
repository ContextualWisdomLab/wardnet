use std::sync::Arc;

use axum::{
    body::{Body, to_bytes},
    http::{HeaderValue, Request, StatusCode, header::CONTENT_TYPE},
};
use tower::ServiceExt;
use wardnet_agent_artifact_admission::{
    AdmissionDecision, AdmissionPolicy, AdmissionState, AuditSink, DecisionKind, MemoryAuditSink,
    ReasonCode, build_app,
};

const ADMIN_TOKEN: &str = "0123456789abcdef0123456789abcdef";

fn state(sink: Arc<dyn AuditSink>) -> AdmissionState {
    AdmissionState::new(
        AdmissionPolicy {
            policy_id: "enterprise-default".to_string(),
            policy_revision: "oversize-audit-test".to_string(),
            ..AdmissionPolicy::default()
        },
        ADMIN_TOKEN.to_string(),
        sink,
        32,
    )
}

#[tokio::test]
async fn oversized_authenticated_request_is_audited_before_payload_too_large_response() {
    let sink = Arc::new(MemoryAuditSink::default());
    let app = build_app(state(sink.clone()));
    let request = Request::builder()
        .method("POST")
        .uri("/v1/admissions")
        .header(CONTENT_TYPE, "application/json")
        .header("x-admin-token", HeaderValue::from_static(ADMIN_TOKEN))
        .body(Body::from(vec![b'x'; 128]))
        .expect("request must build");

    let response = app.oneshot(request).await.expect("router must answer");

    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let bytes = to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("response body must be readable");
    let decision: AdmissionDecision =
        serde_json::from_slice(&bytes).expect("oversized response must be a decision receipt");
    assert_eq!(decision.decision, DecisionKind::Block);
    assert_eq!(
        decision.reason_codes,
        vec![ReasonCode::RequestBodyTooLarge]
    );

    let records = sink.records().expect("audit snapshot must succeed");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].decision, DecisionKind::Block);
    assert_eq!(
        records[0].reason_codes,
        vec![ReasonCode::RequestBodyTooLarge]
    );
    assert_eq!(records[0].request_id, "unavailable:request_body_too_large");
    assert!(records[0].request_body_sha256.is_none());
}
