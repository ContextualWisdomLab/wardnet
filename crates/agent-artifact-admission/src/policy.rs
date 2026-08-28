use crate::{
    AdmissionDecision, AdmissionPolicy, ApprovedArtifact, ArtifactCoordinate, DecisionKind,
    InstallIntent, InstructionSourceKind, ReasonCode,
};
use url::Url;

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

    validate_source(intent, &mut reason_codes);
    validate_command_path(intent, &mut reason_codes);
    validate_safety_flags(intent, &mut reason_codes);

    if !policy.approved_manifests.iter().any(|manifest| {
        manifest.workspace_id == intent.workspace_id && manifest.sha256 == intent.manifest_sha256
    }) {
        push_reason(&mut reason_codes, ReasonCode::ManifestNotApproved);
    }

    if intent.artifacts.is_empty()
        || intent
            .artifacts
            .iter()
            .any(|artifact| !artifact_is_approved(artifact, intent, policy))
    {
        push_reason(&mut reason_codes, ReasonCode::ArtifactNotApproved);
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
        normalized_source_uri: normalized_source_uri(intent),
        command_sha256: sha256_hex(intent.argv.join("\u{1f}").as_bytes()),
        artifact_count: intent.artifacts.len(),
    }
}

fn validate_source(intent: &InstallIntent, reason_codes: &mut Vec<ReasonCode>) {
    if !requires_remote_source_validation(intent.source.kind) {
        return;
    }

    match intent.source.uri.as_deref() {
        Some(uri) if is_valid_remote_source_uri(uri) => {}
        Some(_) => push_reason(reason_codes, ReasonCode::InvalidSourceUri),
        None => push_reason(reason_codes, ReasonCode::MissingSourceUri),
    }

    if !intent
        .source
        .content_sha256
        .as_deref()
        .is_some_and(crate::is_sha256_hex)
    {
        push_reason(reason_codes, ReasonCode::MissingSourceDigest);
    }
}

fn validate_command_path(intent: &InstallIntent, reason_codes: &mut Vec<ReasonCode>) {
    let Some(executable) = intent.argv.first().map(String::as_str) else {
        return;
    };
    if is_forbidden_executable(executable) || requests_inline_eval(executable, &intent.argv[1..]) {
        push_reason(reason_codes, ReasonCode::ForbiddenCommand);
    }
}

fn validate_safety_flags(intent: &InstallIntent, reason_codes: &mut Vec<ReasonCode>) {
    let Some(executable) = intent.argv.first().map(String::as_str) else {
        return;
    };
    let args = &intent.argv[1..];
    let missing = match executable {
        "npm" | "pnpm" | "yarn" | "bun" => !args.iter().any(|arg| arg == "--ignore-scripts"),
        "pip" | "pip3" => !args.iter().any(|arg| arg == "--require-hashes"),
        "cargo" if args.first().is_some_and(|arg| arg == "install") => {
            !args.iter().any(|arg| arg == "--locked")
        }
        "uv" if args.first().is_some_and(|arg| arg == "pip") => {
            !args.iter().any(|arg| arg == "--require-hashes")
        }
        _ => false,
    };
    if missing {
        push_reason(reason_codes, ReasonCode::MissingSafetyFlag);
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

fn requires_remote_source_validation(kind: InstructionSourceKind) -> bool {
    matches!(
        kind,
        InstructionSourceKind::LlmsTxt
            | InstructionSourceKind::LlmsFullTxt
            | InstructionSourceKind::WebPage
            | InstructionSourceKind::IssueComment
    )
}

fn normalized_source_uri(intent: &InstallIntent) -> Option<String> {
    let uri = intent.source.uri.as_deref()?;
    let mut url = Url::parse(uri).ok()?;
    url.set_query(None);
    url.set_fragment(None);
    Some(url.to_string())
}

fn is_valid_remote_source_uri(uri: &str) -> bool {
    let Ok(url) = Url::parse(uri) else {
        return false;
    };
    url.scheme() == "https"
        && url.username().is_empty()
        && url.password().is_none()
        && url.host_str().is_some()
}

fn is_forbidden_executable(executable: &str) -> bool {
    matches!(
        executable,
        "sh" | "bash"
            | "zsh"
            | "cmd"
            | "powershell"
            | "pwsh"
            | "curl"
            | "wget"
            | "aria2c"
            | "ftp"
            | "scp"
            | "npx"
            | "pnpx"
            | "bunx"
    )
}

fn requests_inline_eval(executable: &str, args: &[String]) -> bool {
    matches!(
        executable,
        "python" | "python3" | "node" | "ruby" | "perl" | "php"
    ) && args
        .iter()
        .any(|arg| matches!(arg.as_str(), "-c" | "-e" | "--eval" | "--execute"))
}

fn push_reason(reason_codes: &mut Vec<ReasonCode>, reason: ReasonCode) {
    if !reason_codes.contains(&reason) {
        reason_codes.push(reason);
    }
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
