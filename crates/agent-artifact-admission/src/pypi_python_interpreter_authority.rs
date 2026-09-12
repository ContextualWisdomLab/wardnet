use crate::InstallIntent;

/// Return whether a direct-pip General Option token selects the Python interpreter.
///
/// The reviewed pip parser defines `--python` as a General Option that runs pip
/// with the selected interpreter. Python `optparse` accepts unambiguous long-option
/// prefixes; in the pinned pip General Options set, `--p` is ambiguous with
/// `--proxy`, while `--py` through `--python` uniquely select `--python`.
/// This matcher is intentionally scoped to pip and is not shared with uv or any
/// other package-manager grammar.
pub(crate) fn matches_pip_python_interpreter_option(argument: &str) -> bool {
    let option = argument
        .split_once('=')
        .map_or(argument, |(option, _)| option);
    matches!(option, "--py" | "--pyt" | "--pyth" | "--pytho" | "--python")
}

/// Detect caller-selected Python-interpreter authority after direct-pip global
/// option normalization has produced the ordinary `pip install` policy shape.
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

    intent
        .argv
        .iter()
        .skip(2)
        .any(|argument| matches_pip_python_interpreter_option(argument))
}

#[cfg(test)]
mod tests {
    use super::matches_pip_python_interpreter_option;

    #[test]
    fn pip_python_prefix_matcher_is_bounded_to_verified_unambiguous_language() {
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
}
