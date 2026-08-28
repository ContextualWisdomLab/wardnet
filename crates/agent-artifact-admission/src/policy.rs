use crate::{
    AdmissionDecision, AdmissionPolicy, ApprovedArtifact, ArtifactCoordinate, DecisionKind,
    InstallIntent, ReasonCode,
};

/// Compute a deterministic fail-closed admission decision for one install intent.
pub fn admission_decision(policy: &AdmissionPolicy, intent: &InstallIntent) -> AdmissionDecision {
    let mut reason_codes = Vec::new();
    match intent.argv.first() {
        Some(executable)
            if policy
                .allowed_executables
                .iter()
                .any(|allowed| allowed == executable) => {}
        Some(_) => reason_codes.push(ReasonCode::ExecutableNotAllowed),
        None => reason_codes.push(ReasonCode::MissingExecutable),
    }

    if !policy.approved_manifests.iter().any(|manifest| {
        manifest.workspace_id == intent.workspace_id && manifest.sha256 == intent.manifest_sha256
    }) {
        reason_codes.push(ReasonCode::ManifestNotApproved);
    }

    if intent.artifacts.is_empty()
        || intent
            .artifacts
            .iter()
            .any(|artifact| !artifact_is_approved(artifact, intent, policy))
    {
        reason_codes.push(ReasonCode::ArtifactNotApproved);
    }

    let decision = if reason_codes.is_empty() {
        DecisionKind::Allow
    } else {
        DecisionKind::Block
    };
    AdmissionDecision {
        request_id: intent.request_id.clone(),
        decision,
        reason_codes,
        policy_id: policy.policy_id.clone(),
        policy_revision: policy.policy_revision.clone(),
        normalized_source_uri: intent.source.uri.clone(),
        command_sha256: sha256_hex(intent.argv.join("\u{1f}").as_bytes()),
        artifact_count: intent.artifacts.len(),
    }
}

fn artifact_is_approved(
    artifact: &ArtifactCoordinate,
    intent: &InstallIntent,
    policy: &AdmissionPolicy,
) -> bool {
    if intent
        .argv
        .iter()
        .filter(|token| *token == &artifact.artifact_argument)
        .count()
        != 1
    {
        return false;
    }
    policy.approved_artifacts.iter().any(|approved| {
        exact_artifact_match(approved, artifact)
            && approved.artifact_argument == artifact.artifact_argument
    })
}

fn exact_artifact_match(approved: &ApprovedArtifact, artifact: &ArtifactCoordinate) -> bool {
    approved.ecosystem == artifact.ecosystem
        && approved.name == artifact.name
        && approved.version == artifact.version
        && approved.registry_url == artifact.registry_url
        && approved.owner == artifact.owner
        && approved.sha256 == artifact.sha256
}

/// Return `true` when `value` is a lowercase hexadecimal SHA-256 digest.
pub fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value.as_bytes().iter().all(u8::is_ascii_hexdigit)
        && value == value.to_ascii_lowercase()
}

/// Hex-encode the SHA-256 digest of `input`.
pub fn sha256_hex(input: &[u8]) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, input);
    let mut output = String::with_capacity(64);
    for byte in digest.as_ref() {
        use std::fmt::Write as _;
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}
