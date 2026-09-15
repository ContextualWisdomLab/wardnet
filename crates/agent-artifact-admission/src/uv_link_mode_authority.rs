use crate::InstallIntent;
use crate::policy::uv_active_command_index;

/// Return whether submitted `uv pip install` argv explicitly selects symlink
/// materialization from uv's shared cache. Reviewed top-level uv options remain
/// visible to causal evidence attribution even though they do not widen the
/// supported install-command grammar.
pub(crate) fn requests_unapproved_uv_symlink_link_mode(intent: &InstallIntent) -> bool {
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
    if arguments.get(command_index).map(String::as_str) != Some("pip")
        || arguments.get(command_index + 1).map(String::as_str) != Some("install")
    {
        return false;
    }

    let install_arguments = &arguments[command_index + 2..];
    install_arguments
        .iter()
        .enumerate()
        .any(|(index, argument)| {
            argument == "--link-mode=symlink"
                || (argument == "--link-mode"
                    && install_arguments
                        .get(index + 1)
                        .is_some_and(|value| value == "symlink"))
        })
}

#[cfg(test)]
mod tests {
    use super::requests_unapproved_uv_symlink_link_mode;
    use crate::{ArtifactCoordinate, InstallIntent, InstructionSource, InstructionSourceKind};

    fn intent(argv: &[&str]) -> InstallIntent {
        InstallIntent {
            request_id: "req-uv-link-mode-unit".to_string(),
            actor_id: "agent:wardnet:admission".to_string(),
            workspace_id: "ContextualWisdomLab/wardnet".to_string(),
            operation: "install".to_string(),
            argv: argv.iter().map(|value| (*value).to_string()).collect(),
            manifest_sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_string(),
            source: InstructionSource {
                kind: InstructionSourceKind::ReviewedConfig,
                uri: None,
                content_sha256: None,
            },
            artifacts: vec![ArtifactCoordinate {
                ecosystem: "pypi".to_string(),
                name: "cwl-example".to_string(),
                version: "1.2.3".to_string(),
                registry_url: "https://pypi.org/simple".to_string(),
                owner: "ContextualWisdomLab".to_string(),
                sha256: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                    .to_string(),
                artifact_argument: "cwl-example==1.2.3".to_string(),
            }],
        }
    }

    #[test]
    fn uv_symlink_matcher_accepts_only_explicit_symlink_materialization() {
        for argv in [
            vec![
                "uv",
                "pip",
                "install",
                "cwl-example==1.2.3",
                "--link-mode=symlink",
            ],
            vec![
                "uv",
                "pip",
                "install",
                "cwl-example==1.2.3",
                "--link-mode",
                "symlink",
            ],
            vec![
                "uv",
                "--color",
                "never",
                "pip",
                "install",
                "cwl-example==1.2.3",
                "--link-mode=symlink",
            ],
        ] {
            assert!(requests_unapproved_uv_symlink_link_mode(&intent(&argv)));
        }

        for argv in [
            vec![
                "uv",
                "pip",
                "install",
                "cwl-example==1.2.3",
                "--link-mode=copy",
            ],
            vec![
                "uv",
                "--color",
                "never",
                "pip",
                "sync",
                "requirements.txt",
                "--link-mode=symlink",
            ],
            vec![
                "uv",
                "--color",
                "never",
                "pip",
                "install",
                "cwl-example==1.2.3",
                "--link-modex=symlink",
            ],
            vec![
                "pip",
                "install",
                "cwl-example==1.2.3",
                "--link-mode=symlink",
            ],
        ] {
            assert!(!requests_unapproved_uv_symlink_link_mode(&intent(&argv)));
        }
    }
}
