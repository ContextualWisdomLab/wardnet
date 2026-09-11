use crate::InstallIntent;

/// Return whether an approved uv install explicitly selects symlink
/// materialization from uv's shared cache.
pub(crate) fn requests_unapproved_uv_symlink_link_mode(intent: &InstallIntent) -> bool {
    let Some(executable) = intent.argv.first().map(String::as_str) else {
        return false;
    };
    if executable != "uv" {
        return false;
    }

    let arguments = &intent.argv[1..];
    if !arguments.first().is_some_and(|argument| argument == "pip")
        || !arguments
            .get(1)
            .is_some_and(|argument| argument == "install")
    {
        return false;
    }

    let install_arguments = &arguments[2..];
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
        assert!(requests_unapproved_uv_symlink_link_mode(&intent(&[
            "uv",
            "pip",
            "install",
            "cwl-example==1.2.3",
            "--link-mode=symlink",
        ])));
        assert!(requests_unapproved_uv_symlink_link_mode(&intent(&[
            "uv",
            "pip",
            "install",
            "cwl-example==1.2.3",
            "--link-mode",
            "symlink",
        ])));
        assert!(!requests_unapproved_uv_symlink_link_mode(&intent(&[
            "uv",
            "pip",
            "install",
            "cwl-example==1.2.3",
            "--link-mode=copy",
        ])));
        assert!(!requests_unapproved_uv_symlink_link_mode(&intent(&[
            "pip",
            "install",
            "cwl-example==1.2.3",
            "--link-mode=symlink",
        ])));
    }
}
