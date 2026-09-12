use crate::InstallIntent;

/// Return whether a direct-pip General Option token selects the Python interpreter.
///
/// The reviewed pip parser defines `--python` as a General Option that runs pip
/// with the selected interpreter. Python `optparse` accepts unambiguous long-option
/// prefixes; in the pinned pip General Options set, `--p` is ambiguous with
/// `--proxy`, while `--py` through `--python` uniquely select `--python`.
/// This matcher is intentionally scoped to pip's pre-command General Options and
/// is not shared with post-command or other package-manager grammar.
pub(crate) fn matches_pip_python_interpreter_option(argument: &str) -> bool {
    let option = argument
        .split_once('=')
        .map_or(argument, |(option, _)| option);
    matches!(
        option,
        "--py" | "--pyt" | "--pyth" | "--pytho" | "--python"
    )
}

/// Normalize an exact post-command `pip install --python VALUE` selector only in
/// Wardnet's internal policy copy.
///
/// pip's install-command parser also defines `--python-version`, so abbreviated
/// `--py...` spellings are intentionally not accepted in this post-command seam.
/// Attaching the consumed value prevents the selected interpreter path from being
/// mistaken for a package operand while the public decision wrapper preserves the
/// exact caller-submitted argv as audit identity. The `--` option terminator ends
/// this grammar. This performs no interpreter discovery, execution, environment
/// mutation, or filesystem access.
pub(crate) fn normalize_reviewed_post_command_pip_python_interpreter_value(
    intent: &InstallIntent,
) -> Option<InstallIntent> {
    let executable = intent.argv.first()?.as_str();
    if !matches!(executable, "pip" | "pip3")
        || !intent
            .argv
            .get(1)
            .is_some_and(|argument| argument == "install")
    {
        return None;
    }

    let mut argv = intent.argv.clone();
    let mut index = 2;
    let mut changed = false;
    while index < argv.len() {
        if argv[index] == "--" {
            break;
        }
        if argv[index] != "--python" {
            index += 1;
            continue;
        }

        let value = argv.get(index + 1)?.clone();
        if value.is_empty() || value.starts_with('-') {
            return None;
        }

        argv[index] = format!("--python={value}");
        argv.remove(index + 1);
        changed = true;
        index += 1;
    }

    if !changed {
        return None;
    }

    let mut normalized = intent.clone();
    normalized.argv = argv;
    Some(normalized)
}

/// Detect caller-selected Python-interpreter authority after direct-pip global
/// option normalization has produced the ordinary `pip install` policy shape.
///
/// At this parser phase only exact `--python` is authoritative: abbreviated
/// `--py...` forms are ambiguous with `--python-version`. Tokens after `--` are
/// positional grammar and are never classified as interpreter authority.
pub(crate) fn requests_unapproved_pypi_python_interpreter_authority(
    intent: &InstallIntent,
) -> bool {
    let Some(executable) = intent.argv.first().map(String::as_str) else {
        return false;
    };
    if !matches!(executable, "pip" | "pip3")
        || !intent
            .argv
            .get(1)
            .is_some_and(|argument| argument == "install")
    {
        return false;
    }

    for argument in intent.argv.iter().skip(2) {
        if argument == "--" {
            break;
        }
        if argument == "--python"
            || argument
                .split_once('=')
                .is_some_and(|(option, value)| option == "--python" && !value.is_empty())
        {
            return true;
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::{
        matches_pip_python_interpreter_option,
        normalize_reviewed_post_command_pip_python_interpreter_value,
        requests_unapproved_pypi_python_interpreter_authority,
    };
    use crate::{ArtifactCoordinate, InstallIntent, InstructionSource, InstructionSourceKind};

    #[test]
    fn pip_python_prefix_matcher_is_bounded_to_verified_unambiguous_global_language() {
        for accepted in ["--py", "--pyt", "--pyth", "--pytho", "--python"] {
            assert!(matches_pip_python_interpreter_option(accepted));
            assert!(matches_pip_python_interpreter_option(&format!(
                "{accepted}=/tmp/python"
            )));
        }

        for rejected in ["--p", "--proxy", "--python-version", "-p", "--pythonx"] {
            assert!(!matches_pip_python_interpreter_option(rejected));
        }
    }

    #[test]
    fn post_command_normalizer_is_exact_and_consumes_only_python_value() {
        let intent = test_intent(vec![
            "pip",
            "install",
            "--python",
            "/tmp/python",
            "cwl-example==1.2.3",
        ]);
        let normalized = normalize_reviewed_post_command_pip_python_interpreter_value(&intent)
            .expect("exact post-command --python should normalize");
        assert_eq!(
            normalized.argv,
            vec![
                "pip",
                "install",
                "--python=/tmp/python",
                "cwl-example==1.2.3"
            ]
        );

        for unreviewed in ["--py", "--pyt", "--pyth", "--pytho", "--python-version"] {
            let intent = test_intent(vec![
                "pip",
                "install",
                unreviewed,
                "/tmp/python",
                "cwl-example==1.2.3",
            ]);
            assert!(
                normalize_reviewed_post_command_pip_python_interpreter_value(&intent).is_none(),
                "post-command {unreviewed} must not inherit exact --python grammar"
            );
        }
    }

    #[test]
    fn post_command_authority_is_exact_and_stops_at_option_terminator() {
        assert!(requests_unapproved_pypi_python_interpreter_authority(
            &test_intent(vec![
                "pip",
                "install",
                "--python=/tmp/python",
                "cwl-example==1.2.3",
            ])
        ));

        for unreviewed in ["--py", "--pyt", "--pyth", "--pytho"] {
            assert!(!requests_unapproved_pypi_python_interpreter_authority(
                &test_intent(vec![
                    "pip",
                    "install",
                    unreviewed,
                    "/tmp/python",
                    "cwl-example==1.2.3",
                ])
            ));
        }

        assert!(!requests_unapproved_pypi_python_interpreter_authority(
            &test_intent(vec![
                "pip",
                "install",
                "--",
                "--python",
                "/tmp/python",
                "cwl-example==1.2.3",
            ])
        ));
    }

    #[test]
    fn post_command_normalizer_respects_option_termination() {
        let intent = test_intent(vec![
            "pip",
            "install",
            "--",
            "--python",
            "/tmp/python",
            "cwl-example==1.2.3",
        ]);
        assert!(normalize_reviewed_post_command_pip_python_interpreter_value(&intent).is_none());
    }

    fn test_intent(argv: Vec<&str>) -> InstallIntent {
        InstallIntent {
            request_id: "req-python-normalizer".to_string(),
            actor_id: "agent:wardnet:admission".to_string(),
            workspace_id: "ContextualWisdomLab/wardnet".to_string(),
            operation: "install".to_string(),
            argv: argv.into_iter().map(str::to_string).collect(),
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
}
