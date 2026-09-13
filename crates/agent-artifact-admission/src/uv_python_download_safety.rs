use crate::InstallIntent;
use crate::policy::uv_active_command_index;

/// Return whether an active `uv pip install` can implicitly acquire a Python
/// distribution that is absent from the reviewed artifact set.
pub(crate) fn misses_required_uv_python_download_guard(intent: &InstallIntent) -> bool {
    let Some(executable) = intent.argv.first().map(String::as_str) else {
        return false;
    };
    if executable != "uv" {
        return false;
    }

    let arguments = &intent.argv[1..];
    let Some(command_index) = uv_active_command_index(arguments) else {
        return false;
    };
    if arguments[command_index] != "pip"
        || !arguments
            .get(command_index + 1)
            .is_some_and(|argument| argument == "install")
    {
        return false;
    }

    !arguments
        .iter()
        .take_while(|argument| argument.as_str() != "--")
        .any(|argument| argument == "--no-python-downloads")
}

#[cfg(test)]
mod tests {
    use super::misses_required_uv_python_download_guard;
    use crate::{ArtifactCoordinate, InstallIntent, InstructionSource, InstructionSourceKind};

    #[test]
    fn exact_guard_is_required_for_active_uv_pip_install() {
        for arguments in [
            vec!["uv", "pip", "install", "pkg==1"],
            vec!["uv", "pip", "install", "pkg==1", "--no-python-download"],
            vec![
                "uv",
                "pip",
                "install",
                "pkg==1",
                "--no-python-downloads=false",
            ],
            vec![
                "uv",
                "pip",
                "install",
                "pkg==1",
                "--",
                "--no-python-downloads",
            ],
        ] {
            assert!(
                misses_required_uv_python_download_guard(&intent(&arguments)),
                "missing, near, assigned, or option-terminated selectors must not authorize implicit Python acquisition: {arguments:?}"
            );
        }

        for arguments in [
            vec![
                "uv",
                "pip",
                "install",
                "pkg==1",
                "--no-python-downloads",
            ],
            vec![
                "uv",
                "--no-python-downloads",
                "pip",
                "install",
                "pkg==1",
            ],
            vec![
                "uv",
                "--color",
                "never",
                "--no-python-downloads",
                "pip",
                "install",
                "pkg==1",
            ],
        ] {
            assert!(
                !misses_required_uv_python_download_guard(&intent(&arguments)),
                "the exact uv-owned disable flag must satisfy the artifact-cardinality guard: {arguments:?}"
            );
        }
    }

    #[test]
    fn non_install_uv_commands_do_not_claim_python_download_safety_authority() {
        for arguments in [
            vec!["uv", "pip", "sync", "pkg==1"],
            vec!["uv", "run", "pkg==1"],
            vec!["pip", "install", "pkg==1"],
        ] {
            assert!(
                !misses_required_uv_python_download_guard(&intent(&arguments)),
                "only active uv pip install belongs to this admission guard: {arguments:?}"
            );
        }
    }

    fn intent(arguments: &[&str]) -> InstallIntent {
        InstallIntent {
            request_id: "req-uv-python-download-unit".to_string(),
            actor_id: "agent:wardnet:admission".to_string(),
            workspace_id: "ContextualWisdomLab/wardnet".to_string(),
            operation: "install".to_string(),
            argv: arguments
                .iter()
                .map(|argument| (*argument).to_string())
                .collect(),
            manifest_sha256:
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            source: InstructionSource {
                kind: InstructionSourceKind::ReviewedConfig,
                uri: None,
                content_sha256: None,
            },
            artifacts: vec![ArtifactCoordinate {
                ecosystem: "pypi".to_string(),
                name: "pkg".to_string(),
                version: "1".to_string(),
                registry_url: "https://pypi.org/simple".to_string(),
                owner: "ContextualWisdomLab".to_string(),
                sha256:
                    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                        .to_string(),
                artifact_argument: "pkg==1".to_string(),
            }],
        }
    }
}
