use std::collections::BTreeSet;

use crate::{
    AdmissionDecision, AdmissionPolicy, ApprovedArtifact, ArtifactCoordinate, DecisionKind,
    InstallIntent, InstructionSourceKind, ReasonCode,
};
use url::Url;

const MAX_REQUEST_ID_BYTES: usize = 256;
const MAX_ACTOR_ID_BYTES: usize = 512;
const MAX_WORKSPACE_ID_BYTES: usize = 512;
const MAX_OPERATION_BYTES: usize = 32;
const MAX_ARGV_TOKENS: usize = 128;
const MAX_ARG_BYTES: usize = 4 * 1024;
const MAX_ARGV_BYTES: usize = 64 * 1024;
const MAX_SOURCE_URI_BYTES: usize = 4 * 1024;
const MAX_ARTIFACTS: usize = 64;
const MAX_ECOSYSTEM_BYTES: usize = 64;
const MAX_ARTIFACT_NAME_BYTES: usize = 512;
const MAX_VERSION_BYTES: usize = 256;
const MAX_OWNER_BYTES: usize = 512;
const MAX_ARTIFACT_ARGUMENT_BYTES: usize = 1024;

/// Compute a deterministic fail-closed admission decision for one install intent.
pub fn admission_decision(policy: &AdmissionPolicy, intent: &InstallIntent) -> AdmissionDecision {
    let mut reason_codes = validate_install_intent(intent);

    match intent.argv.first() {
        Some(executable)
            if policy
                .allowed_executables
                .iter()
                .any(|allowed| allowed == executable) => {}
        Some(_) => push_reason(&mut reason_codes, ReasonCode::ExecutableNotAllowed),
        None => push_reason(&mut reason_codes, ReasonCode::MissingExecutable),
    }

    validate_source(intent, &mut reason_codes);
    validate_command_path(intent, &mut reason_codes);
    validate_safety_flags(intent, &mut reason_codes);
    validate_artifact_operands(intent, &mut reason_codes);

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
        request_id: auditable_identifier("request", &intent.request_id, MAX_REQUEST_ID_BYTES),
        decision,
        reason_codes,
        policy_id: policy.policy_id.clone(),
        policy_revision: policy.policy_revision.clone(),
        normalized_source_uri: normalized_source_uri(intent),
        command_sha256: sha256_hex(intent.argv.join("\u{1f}").as_bytes()),
        artifact_count: intent.artifacts.len(),
    }
}

/// Validate the bounded structural contract independently of policy membership.
pub fn validate_install_intent(intent: &InstallIntent) -> Vec<ReasonCode> {
    let mut reason_codes = Vec::new();

    if !valid_text_field(&intent.request_id, MAX_REQUEST_ID_BYTES)
        || !valid_text_field(&intent.actor_id, MAX_ACTOR_ID_BYTES)
        || !valid_text_field(&intent.workspace_id, MAX_WORKSPACE_ID_BYTES)
        || !valid_text_field(&intent.operation, MAX_OPERATION_BYTES)
    {
        push_reason(&mut reason_codes, ReasonCode::InvalidRequest);
    }

    if intent.operation != "install" {
        push_reason(&mut reason_codes, ReasonCode::InvalidOperation);
    }

    if intent.argv.is_empty() {
        push_reason(&mut reason_codes, ReasonCode::MissingExecutable);
    } else if intent.argv.len() > MAX_ARGV_TOKENS
        || intent
            .argv
            .iter()
            .any(|argument| !valid_text_field(argument, MAX_ARG_BYTES) || argument.contains('\0'))
        || intent.argv.iter().map(String::len).sum::<usize>() > MAX_ARGV_BYTES
    {
        push_reason(&mut reason_codes, ReasonCode::InvalidRequest);
    }

    if !is_sha256_hex(&intent.manifest_sha256) {
        push_reason(&mut reason_codes, ReasonCode::InvalidManifestDigest);
    }

    if intent
        .source
        .uri
        .as_deref()
        .is_some_and(|uri| uri.len() > MAX_SOURCE_URI_BYTES || uri.chars().any(char::is_control))
    {
        push_reason(&mut reason_codes, ReasonCode::InvalidSourceUri);
    }

    if intent.artifacts.is_empty() || intent.artifacts.len() > MAX_ARTIFACTS {
        push_reason(&mut reason_codes, ReasonCode::InvalidArtifact);
    }

    let mut artifact_identities = BTreeSet::new();
    let mut artifact_arguments = BTreeSet::new();
    for artifact in &intent.artifacts {
        if !valid_artifact_coordinate(artifact) {
            push_reason(&mut reason_codes, ReasonCode::InvalidArtifact);
        }
        let identity = (
            artifact.ecosystem.as_str(),
            artifact.name.as_str(),
            artifact.version.as_str(),
            artifact.registry_url.as_str(),
            artifact.owner.as_str(),
            artifact.sha256.as_str(),
        );
        if !artifact_identities.insert(identity)
            || !artifact_arguments.insert(artifact.artifact_argument.as_str())
        {
            push_reason(&mut reason_codes, ReasonCode::DuplicateArtifact);
        }
    }

    reason_codes
}

fn validate_source(intent: &InstallIntent, reason_codes: &mut Vec<ReasonCode>) {
    if !requires_remote_source_validation(intent.source.kind) {
        return;
    }

    match intent.source.uri.as_deref() {
        Some(uri) if normalize_https_source_uri(uri).is_some() => {}
        Some(_) => push_reason(reason_codes, ReasonCode::InvalidSourceUri),
        None => push_reason(reason_codes, ReasonCode::MissingSourceUri),
    }

    if !intent
        .source
        .content_sha256
        .as_deref()
        .is_some_and(is_sha256_hex)
    {
        push_reason(reason_codes, ReasonCode::MissingSourceDigest);
    }
}

fn validate_command_path(intent: &InstallIntent, reason_codes: &mut Vec<ReasonCode>) {
    let Some(executable) = intent.argv.first().map(String::as_str) else {
        return;
    };
    let arguments = &intent.argv[1..];
    if is_permanently_forbidden_executable(executable)
        || requests_inline_eval(executable, arguments)
        || !supported_install_command(executable, arguments)
    {
        push_reason(reason_codes, ReasonCode::ForbiddenCommand);
    }
    if requests_alternate_trust_root(executable, arguments) {
        push_reason(reason_codes, ReasonCode::AlternateTrustRoot);
    }
    if requests_alternate_install_root(executable, arguments) {
        push_reason(reason_codes, ReasonCode::AlternateInstallRoot);
    }
}

fn validate_safety_flags(intent: &InstallIntent, reason_codes: &mut Vec<ReasonCode>) {
    let Some(executable) = intent.argv.first().map(String::as_str) else {
        return;
    };
    let arguments = &intent.argv[1..];
    let missing = match executable {
        "npm" | "pnpm" | "yarn" | "bun" => {
            !has_unambiguous_boolean_safety_flag(arguments, "--ignore-scripts")
        }
        "pip" | "pip3" => !arguments
            .iter()
            .any(|argument| argument == "--require-hashes"),
        "cargo"
            if arguments
                .first()
                .is_some_and(|argument| argument == "install") =>
        {
            !arguments.iter().any(|argument| argument == "--locked")
        }
        "uv" if arguments.first().is_some_and(|argument| argument == "pip")
            && arguments
                .get(1)
                .is_some_and(|argument| argument == "install") =>
        {
            !arguments
                .iter()
                .any(|argument| argument == "--require-hashes")
        }
        "docker" | "podman" if arguments.first().is_some_and(|argument| argument == "pull") => {
            intent.artifacts.is_empty()
                || intent.artifacts.iter().any(|artifact| {
                    artifact.artifact_argument
                        != format!("{}@sha256:{}", artifact.name, artifact.sha256)
                        || intent
                            .argv
                            .iter()
                            .filter(|token| *token == &artifact.artifact_argument)
                            .count()
                            != 1
                })
        }
        _ => false,
    };
    if missing {
        push_reason(reason_codes, ReasonCode::MissingSafetyFlag);
    }
}

fn validate_artifact_operands(intent: &InstallIntent, reason_codes: &mut Vec<ReasonCode>) {
    let Some(executable) = intent.argv.first().map(String::as_str) else {
        return;
    };
    let arguments = &intent.argv[1..];
    let command_prefix_len = match executable {
        "uv"
            if arguments.first().is_some_and(|argument| argument == "pip")
                && arguments
                    .get(1)
                    .is_some_and(|argument| argument == "install") =>
        {
            2
        }
        "npm" | "pnpm" | "yarn" | "bun" | "pip" | "pip3" | "cargo" | "docker"
        | "podman" => 1,
        _ => return,
    };

    let declared_arguments: BTreeSet<&str> = intent
        .artifacts
        .iter()
        .map(|artifact| artifact.artifact_argument.as_str())
        .collect();
    let positional_arguments: Vec<&str> = arguments
        .iter()
        .skip(command_prefix_len)
        .filter(|argument| !argument.starts_with('-'))
        .map(String::as_str)
        .collect();

    if intent
        .artifacts
        .iter()
        .any(|artifact| !artifact_ecosystem_matches_executable(executable, &artifact.ecosystem))
        || requests_indirect_artifact_source(executable, arguments)
        || positional_arguments.len() != declared_arguments.len()
        || positional_arguments
            .iter()
            .any(|argument| !declared_arguments.contains(argument))
    {
        push_reason(reason_codes, ReasonCode::ArtifactNotApproved);
    }
}

fn artifact_ecosystem_matches_executable(executable: &str, ecosystem: &str) -> bool {
    match executable {
        "npm" | "pnpm" | "yarn" | "bun" => ecosystem == "npm",
        "pip" | "pip3" | "uv" => ecosystem == "pypi",
        "cargo" => ecosystem == "cargo",
        "docker" | "podman" => ecosystem == "oci",
        _ => false,
    }
}

fn requests_indirect_artifact_source(executable: &str, arguments: &[String]) -> bool {
    let contains_flag = |flags: &[&str]| {
        arguments
            .iter()
            .any(|argument| flags.iter().any(|flag| matches_cli_flag(argument, flag)))
    };

    match executable {
        "pip" | "pip3" => contains_flag(&[
            "-r",
            "--requirement",
            "-e",
            "--editable",
            "--requirements-from-script",
        ]),
        "uv"
            if arguments.first().is_some_and(|argument| argument == "pip")
                && arguments
                    .get(1)
                    .is_some_and(|argument| argument == "install") =>
        {
            contains_flag(&[
                "-r",
                "--requirement",
                "--requirements",
                "-e",
                "--editable",
                "--group",
                "--project",
            ])
        }
        _ => false,
    }
}

fn has_unambiguous_boolean_safety_flag(arguments: &[String], flag: &str) -> bool {
    let Some(flag_name) = flag.strip_prefix("--") else {
        return false;
    };
    let negated = format!("--no-{flag_name}");
    let assigned = format!("{flag}=");

    arguments.iter().any(|argument| argument == flag)
        && !arguments
            .iter()
            .any(|argument| argument == &negated || argument.starts_with(&assigned))
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
    intent
        .source
        .uri
        .as_deref()
        .and_then(normalize_https_source_uri)
}

pub(crate) fn normalize_https_source_uri(uri: &str) -> Option<String> {
    let mut url = Url::parse(uri).ok()?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.host_str().is_none()
    {
        return None;
    }
    url.set_query(None);
    url.set_fragment(None);
    Some(url.to_string())
}

pub(crate) fn canonical_registry_url(registry_url: &str) -> Option<String> {
    let url = Url::parse(registry_url).ok()?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return None;
    }
    Some(url.to_string())
}

pub(crate) fn is_permanently_forbidden_executable(executable: &str) -> bool {
    matches!(
        executable.to_ascii_lowercase().as_str(),
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

pub(crate) fn supported_executable(executable: &str) -> bool {
    matches!(
        executable,
        "npm" | "pnpm" | "yarn" | "bun" | "pip" | "pip3" | "uv" | "cargo" | "docker" | "podman"
    )
}

fn supported_install_command(executable: &str, arguments: &[String]) -> bool {
    match executable {
        "npm" => arguments
            .first()
            .is_some_and(|argument| matches!(argument.as_str(), "install" | "i")),
        "pnpm" | "bun" => arguments
            .first()
            .is_some_and(|argument| matches!(argument.as_str(), "add" | "install")),
        "yarn" => arguments.first().is_some_and(|argument| argument == "add"),
        "pip" | "pip3" | "cargo" => arguments
            .first()
            .is_some_and(|argument| argument == "install"),
        "uv" => {
            arguments.first().is_some_and(|argument| argument == "pip")
                && arguments
                    .get(1)
                    .is_some_and(|argument| argument == "install")
        }
        "docker" | "podman" => arguments.first().is_some_and(|argument| argument == "pull"),
        _ => false,
    }
}

fn requests_inline_eval(executable: &str, arguments: &[String]) -> bool {
    matches!(
        executable.to_ascii_lowercase().as_str(),
        "python" | "python3" | "node" | "ruby" | "perl" | "php"
    ) && arguments
        .iter()
        .any(|argument| matches!(argument.as_str(), "-c" | "-e" | "--eval" | "--execute"))
}

fn requests_alternate_trust_root(executable: &str, arguments: &[String]) -> bool {
    const FORBIDDEN_FLAGS: &[&str] = &[
        "--extra-index-url",
        "--index-url",
        "--index",
        "--default-index",
        "--trusted-host",
        "--find-links",
        "--registry",
        "--registry-url",
        "--userconfig",
        "--globalconfig",
        "--git",
        "--path",
        "-i",
        "-f",
    ];
    arguments.iter().any(|argument| {
        FORBIDDEN_FLAGS
            .iter()
            .any(|flag| matches_cli_flag(argument, flag))
    }) || (executable == "bun"
        && arguments
            .iter()
            .any(|argument| matches_cli_flag(argument, "--config")))
        || (executable == "pnpm"
            && arguments
                .iter()
                .any(|argument| argument.starts_with("--config.")))
}

fn requests_alternate_install_root(executable: &str, arguments: &[String]) -> bool {
    let contains_flag = |flags: &[&str]| {
        arguments
            .iter()
            .any(|argument| flags.iter().any(|flag| matches_cli_flag(argument, flag)))
    };

    match executable {
        "npm" => {
            contains_flag(&["-g", "--global", "--prefix", "--workspace", "-w"])
                || arguments
                    .iter()
                    .any(|argument| matches!(argument.as_str(), "--workspaces" | "--workspaces=true"))
                || arguments.iter().any(|argument| argument == "--location=global")
                || arguments.windows(2).any(|pair| {
                    pair[0] == "--location" && pair[1].eq_ignore_ascii_case("global")
                })
        }
        "yarn" => {
            contains_flag(&[
                "-g",
                "--global",
                "--prefix",
                "-W",
                "--ignore-workspace-root-check",
            ]) || arguments.iter().any(|argument| argument == "--location=global")
                || arguments.windows(2).any(|pair| {
                    pair[0] == "--location" && pair[1].eq_ignore_ascii_case("global")
                })
        }
        "pnpm" => {
            contains_flag(&[
                "-g",
                "--global",
                "--prefix",
                "--dir",
                "-C",
                "--filter",
                "-F",
                "--filter-prod",
                "--workspace-root",
                "-w",
                "--recursive",
                "-r",
                "--include-workspace-root",
            ]) || arguments.iter().any(|argument| argument == "--location=global")
                || arguments.windows(2).any(|pair| {
                    pair[0] == "--location" && pair[1].eq_ignore_ascii_case("global")
                })
        }
        "bun" => {
            contains_flag(&[
                "-g",
                "--global",
                "--prefix",
                "--cwd",
                "--filter",
                "-F",
            ]) || arguments.iter().any(|argument| argument == "--location=global")
                || arguments.windows(2).any(|pair| {
                    pair[0] == "--location" && pair[1].eq_ignore_ascii_case("global")
                })
        }
        "pip" | "pip3" => {
            contains_flag(&["--user", "--target", "-t", "--root", "--prefix"])
        }
        "uv" => {
            arguments.first().is_some_and(|argument| argument == "pip")
                && arguments
                    .get(1)
                    .is_some_and(|argument| argument == "install")
                && contains_flag(&[
                    "--user",
                    "--target",
                    "-t",
                    "--root",
                    "--prefix",
                    "--system",
                    "--python",
                    "-p",
                ])
        }
        "cargo" => contains_flag(&["--root", "--config"]),
        _ => false,
    }
}

fn matches_cli_flag(argument: &str, flag: &str) -> bool {
    if argument == flag {
        return true;
    }
    let Some(suffix) = argument.strip_prefix(flag) else {
        return false;
    };
    suffix.starts_with('=') || (is_short_cli_flag(flag) && !suffix.is_empty())
}

fn is_short_cli_flag(flag: &str) -> bool {
    let bytes = flag.as_bytes();
    bytes.len() == 2 && bytes[0] == b'-' && bytes[1] != b'-'
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
        && canonical_registry_url(&approved.registry_url)
            == canonical_registry_url(&artifact.registry_url)
        && approved.owner == artifact.owner
        && approved.sha256 == artifact.sha256
}

pub(crate) fn valid_artifact_coordinate(artifact: &ArtifactCoordinate) -> bool {
    valid_text_field(&artifact.ecosystem, MAX_ECOSYSTEM_BYTES)
        && valid_text_field(&artifact.name, MAX_ARTIFACT_NAME_BYTES)
        && valid_pinned_version(&artifact.version)
        && canonical_registry_url(&artifact.registry_url).is_some()
        && valid_text_field(&artifact.owner, MAX_OWNER_BYTES)
        && is_sha256_hex(&artifact.sha256)
        && valid_text_field(&artifact.artifact_argument, MAX_ARTIFACT_ARGUMENT_BYTES)
}

pub(crate) fn valid_pinned_version(version: &str) -> bool {
    if !valid_text_field(version, MAX_VERSION_BYTES) {
        return false;
    }
    let lowercase = version.to_ascii_lowercase();
    if matches!(
        lowercase.as_str(),
        "latest" | "main" | "master" | "head" | "stable" | "next"
    ) {
        return false;
    }
    version
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b'+'))
}

pub(crate) fn valid_text_field(value: &str, maximum_bytes: usize) -> bool {
    !value.is_empty() && value.len() <= maximum_bytes && !value.chars().any(char::is_control)
}

pub(crate) fn auditable_identifier(label: &str, value: &str, maximum_bytes: usize) -> String {
    if valid_text_field(value, maximum_bytes) {
        value.to_string()
    } else {
        format!("{label}:sha256:{}", sha256_hex(value.as_bytes()))
    }
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
