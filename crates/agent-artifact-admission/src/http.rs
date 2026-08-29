use std::fmt;
use std::future::pending;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use axum::{
    Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::Serialize;
use tokio::net::TcpListener;

use crate::{
    AdmissionDecision, AdmissionPolicy, AdmissionServiceConfig, AuditRecord, AuditSink,
    DecisionKind, FileAuditSink, InstallIntent, ReasonCode, admission_decision,
    build_audit_record, build_malformed_audit_record, load_admin_token, load_config, parse_cli_args,
    sha256_hex, validate_install_intent,
};

const MAX_ADMIN_TOKEN_BYTES: usize = 4096;
const TOKEN_COMPARISON_BYTES: usize = MAX_ADMIN_TOKEN_BYTES + 2;

/// Shared immutable state for the loopback-only admission HTTP service.
#[derive(Clone)]
pub struct AdmissionState {
    policy: Arc<AdmissionPolicy>,
    admin_token: Arc<str>,
    audit_sink: Arc<dyn AuditSink>,
    max_request_body_bytes: usize,
}

impl AdmissionState {
    /// Construct service state from validated policy, credential, and audit dependencies.
    pub fn new(
        policy: AdmissionPolicy,
        admin_token: String,
        audit_sink: Arc<dyn AuditSink>,
        max_request_body_bytes: usize,
    ) -> Self {
        Self {
            policy: Arc::new(policy),
            admin_token: Arc::from(admin_token),
            audit_sink,
            max_request_body_bytes,
        }
    }
}

/// Stable process-level service failure that never exposes paths, tokens, or request content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceError {
    /// Configuration or credential loading failed.
    Configuration,
    /// The validated loopback listener could not be bound.
    Bind,
    /// The HTTP server terminated with an error.
    Serve,
}

impl fmt::Display for ServiceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Configuration => "agent artifact admission configuration failed",
            Self::Bind => "agent artifact admission listener failed",
            Self::Serve => "agent artifact admission service failed",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for ServiceError {}

/// Build the authenticated admission router with its configured request-body limit.
pub fn build_app(state: AdmissionState) -> Router {
    let max_request_body_bytes = state.max_request_body_bytes;
    Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/policy", get(get_policy))
        .route("/v1/admissions", post(create_admission))
        .layer(DefaultBodyLimit::max(max_request_body_bytes))
        .with_state(state)
}

/// Run the standalone loopback service from a validated configuration and credential.
pub async fn run_service(
    config: AdmissionServiceConfig,
    admin_token: String,
) -> Result<(), ServiceError> {
    let address: SocketAddr = config
        .bind_address
        .parse()
        .map_err(|_| ServiceError::Configuration)?;
    if !address.ip().is_loopback() || address.port() == 0 {
        return Err(ServiceError::Configuration);
    }

    let audit_sink: Arc<dyn AuditSink> = Arc::new(FileAuditSink::new(config.audit_log_path));
    let state = AdmissionState::new(
        config.policy,
        admin_token,
        audit_sink,
        config.max_request_body_bytes,
    );
    let listener = TcpListener::bind(address)
        .await
        .map_err(|_| ServiceError::Bind)?;
    axum::serve(listener, build_app(state))
        .with_graceful_shutdown(shutdown_signal())
        .await
        .map_err(|_| ServiceError::Serve)
}

/// Parse strict CLI arguments, load bounded files, and run the standalone service.
pub async fn run_cli(args: &[String]) -> Result<(), ServiceError> {
    let cli = parse_cli_args(args).map_err(|_| ServiceError::Configuration)?;
    let config = load_config(Path::new(&cli.config_path)).map_err(|_| ServiceError::Configuration)?;
    let token = load_admin_token(Path::new(&cli.credentials_path))
        .map_err(|_| ServiceError::Configuration)?;
    run_service(config, token).await
}

#[derive(Serialize)]
struct HealthView {
    status: &'static str,
    policy_id: String,
    policy_revision: String,
    allowed_executable_count: usize,
    approved_manifest_count: usize,
    approved_artifact_count: usize,
}

#[derive(Serialize)]
struct ErrorView {
    error: &'static str,
}

async fn healthz(State(state): State<AdmissionState>) -> Json<HealthView> {
    Json(HealthView {
        status: "ok",
        policy_id: state.policy.policy_id.clone(),
        policy_revision: state.policy.policy_revision.clone(),
        allowed_executable_count: state.policy.allowed_executables.len(),
        approved_manifest_count: state.policy.approved_manifests.len(),
        approved_artifact_count: state.policy.approved_artifacts.len(),
    })
}

async fn get_policy(State(state): State<AdmissionState>, headers: HeaderMap) -> Response {
    if !authenticated(&headers, &state.admin_token) {
        return unauthorized();
    }
    Json((*state.policy).clone()).into_response()
}

async fn create_admission(
    State(state): State<AdmissionState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !authenticated(&headers, &state.admin_token) {
        return unauthorized();
    }

    let intent = match serde_json::from_slice::<InstallIntent>(&body) {
        Ok(intent) => intent,
        Err(_) => return malformed_request_response(&state, &body).await,
    };

    let structural_reasons = validate_install_intent(&intent);
    let decision = admission_decision(&state.policy, &intent);
    let response_status = if structural_reasons.is_empty() {
        StatusCode::OK
    } else {
        StatusCode::BAD_REQUEST
    };
    let record = match build_audit_record(&intent, &decision) {
        Ok(record) => record,
        Err(_) => return audit_unavailable_response(&decision),
    };
    append_before_response(&state, record, decision, response_status).await
}

async fn malformed_request_response(state: &AdmissionState, body: &[u8]) -> Response {
    let body_digest = sha256_hex(body);
    let decision = malformed_decision(&state.policy, &body_digest);
    let record = match build_malformed_audit_record(&state.policy, &body_digest) {
        Ok(record) => record,
        Err(_) => return audit_unavailable_response(&decision),
    };
    append_before_response(state, record, decision, StatusCode::BAD_REQUEST).await
}

async fn append_before_response(
    state: &AdmissionState,
    record: AuditRecord,
    decision: AdmissionDecision,
    status: StatusCode,
) -> Response {
    let sink = state.audit_sink.clone();
    let append_result = tokio::task::spawn_blocking(move || sink.append(&record)).await;
    match append_result {
        Ok(Ok(())) => (status, Json(decision)).into_response(),
        Ok(Err(_)) | Err(_) => audit_unavailable_response(&decision),
    }
}

fn malformed_decision(policy: &AdmissionPolicy, body_digest: &str) -> AdmissionDecision {
    AdmissionDecision {
        request_id: format!("malformed:{body_digest}"),
        decision: DecisionKind::Block,
        reason_codes: vec![ReasonCode::MalformedRequest],
        policy_id: policy.policy_id.clone(),
        policy_revision: policy.policy_revision.clone(),
        normalized_source_uri: None,
        command_sha256: body_digest.to_string(),
        artifact_count: 0,
    }
}

fn audit_unavailable_response(candidate: &AdmissionDecision) -> Response {
    let blocked = AdmissionDecision {
        request_id: candidate.request_id.clone(),
        decision: DecisionKind::Block,
        reason_codes: vec![ReasonCode::AuditUnavailable],
        policy_id: candidate.policy_id.clone(),
        policy_revision: candidate.policy_revision.clone(),
        normalized_source_uri: candidate.normalized_source_uri.clone(),
        command_sha256: candidate.command_sha256.clone(),
        artifact_count: candidate.artifact_count,
    };
    (StatusCode::SERVICE_UNAVAILABLE, Json(blocked)).into_response()
}

fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(ErrorView {
            error: "unauthorized",
        }),
    )
        .into_response()
}

fn authenticated(headers: &HeaderMap, configured: &str) -> bool {
    let mut values = headers.get_all("x-admin-token").iter();
    let Some(value) = values.next() else {
        return false;
    };
    if values.next().is_some() {
        return false;
    }
    let Ok(presented) = value.to_str() else {
        return false;
    };
    constant_time_token_equal(presented, configured)
}

fn constant_time_token_equal(presented: &str, configured: &str) -> bool {
    if presented.len() > MAX_ADMIN_TOKEN_BYTES
        || configured.len() > MAX_ADMIN_TOKEN_BYTES
        || !presented
            .as_bytes()
            .iter()
            .all(|byte| (0x21..=0x7e).contains(byte))
    {
        return false;
    }

    let mut presented_buffer = [0_u8; TOKEN_COMPARISON_BYTES];
    let mut configured_buffer = [0_u8; TOKEN_COMPARISON_BYTES];
    presented_buffer[..2].copy_from_slice(&(presented.len() as u16).to_be_bytes());
    configured_buffer[..2].copy_from_slice(&(configured.len() as u16).to_be_bytes());
    presented_buffer[2..2 + presented.len()].copy_from_slice(presented.as_bytes());
    configured_buffer[2..2 + configured.len()].copy_from_slice(configured.as_bytes());

    ring::constant_time::verify_slices_are_equal(&presented_buffer, &configured_buffer).is_ok()
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let terminate = async {
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(mut signal) => {
                    let _ = signal.recv().await;
                }
                Err(_) => pending::<()>().await,
            }
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = terminate => {}
        }
    }

    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
