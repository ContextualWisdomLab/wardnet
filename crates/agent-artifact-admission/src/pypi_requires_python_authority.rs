use crate::InstallIntent;

/// Return whether a direct pip install explicitly disables publisher-declared
/// `Requires-Python` compatibility enforcement.
pub(crate) fn requests_pypi_requires_python_override(intent: &InstallIntent) -> bool {
    let Some(executable) = intent.argv.first().map(String::as_str) else {
        return false;
    };
    let arguments = &intent.argv[1..];

    matches!(executable, "pip" | "pip3")
        && arguments
            .first()
            .is_some_and(|argument| argument == "install")
        && arguments
            .iter()
            .skip(1)
            .any(|argument| argument == "--ignore-requires-python")
}

#[cfg(test)]
mod tests {
    use super::requests_pypi_requires_python_override;
    use crate::{ArtifactCoordinate, InstallIntent, InstructionSource, InstructionSourceKind};

    #[test]
    fn direct_pip_matches_only_the_canonical_compatibility_override() {
        for executable in ["pip", "pip3"] {
            assert!(requests_pypi_requires_python_override(&intent_with_argv(
                executable,
                vec!["install", "pkg==1", "--ignore-requires-python"]
            )));
            assert!(!requests_pypi_requires_python_override(&intent_with_argv(
                executable,
                vec!["install", "pkg==1", "--ignore-requires-python-extra"]
            )));
        }

        assert!(!requests_pypi_requires_python_override(&intent_with_argv(
            "uv",
            vec!["pip", "install", "pkg==1", "--ignore-requires-python"]
        )));
        assert!(!requests_pypi_requires_python_override(&intent_with_argv(
            "pip",
            vec!["download", "pkg==1", "--ignore-requires-python"]
        )));
    }

    fn intent_with_argv(executable: &str, arguments: Vec<&str>) -> InstallIntent {
        let mut argv = vec![executable.to_string()];
        argv.extend(arguments.into_iter().map(str::to_string));
        InstallIntent {
            request_id: "req-requires-python-unit".to_string(),
            actor_id: "agent:test".to_string(),
            workspace_id: "ContextualWisdomLab/wardnet".to_string(),
            operation: "install".to_string(),
            argv,
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
                owner: "owner".to_string(),
                sha256:
                    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                        .to_string(),
                artifact_argument: "pkg==1".to_string(),
            }],
        }
    }
}
