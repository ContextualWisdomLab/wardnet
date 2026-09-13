use crate::InstallIntent;
use crate::policy::{uv_active_command_index, uv_run_owned_argument_end};

/// Return whether uv is asked to eagerly generate interpreter-dependent bytecode
/// outside the reviewed artifact identity. Supported `uv pip install` keeps its
/// existing option-phase semantics; unsupported `uv run` is classified only
/// through uv-owned argv before delegation to the child command.
pub(crate) fn requests_unapproved_uv_bytecode_compilation(intent: &InstallIntent) -> bool {
    requests_bytecode_compilation(&intent.argv)
}

/// Classify exact uv-owned compile selectors without reinterpreting delegated
/// child argv. The caller remains responsible for the separate allow/deny command
/// decision; this function only supplies causal generated-artifact evidence.
fn requests_bytecode_compilation(argv: &[String]) -> bool {
    let Some(executable) = argv.first().map(String::as_str) else {
        return false;
    };
    if executable != "uv" {
        return false;
    }

    let arguments = &argv[1..];
    if arguments.first().is_some_and(|argument| argument == "pip")
        && arguments
            .get(1)
            .is_some_and(|argument| argument == "install")
    {
        return arguments[2..]
            .iter()
            .take_while(|argument| argument.as_str() != "--")
            .any(|argument| is_compile_selector(argument));
    }

    let Some(run_index) = uv_active_command_index(arguments) else {
        return false;
    };
    if arguments[run_index] != "run" {
        return false;
    }

    arguments[..uv_run_owned_argument_end(arguments, run_index)]
        .iter()
        .any(|argument| is_compile_selector(argument))
}

/// Match only Astral's documented eager bytecode selectors; nearby spellings are
/// intentionally not normalized into policy authority.
fn is_compile_selector(argument: &str) -> bool {
    matches!(argument, "--compile-bytecode" | "--compile")
}

#[cfg(test)]
mod tests {
    use super::requests_bytecode_compilation;

    fn argv(arguments: &[&str]) -> Vec<String> {
        arguments
            .iter()
            .map(|argument| (*argument).to_string())
            .collect()
    }

    #[test]
    fn matcher_preserves_uv_pip_install_option_phase() {
        for arguments in [
            vec!["uv", "pip", "install", "pkg==1", "--compile-bytecode"],
            vec!["uv", "pip", "install", "--compile", "pkg==1"],
        ] {
            assert!(requests_bytecode_compilation(&argv(&arguments)));
        }

        for arguments in [
            vec![],
            vec!["pip", "install", "--compile"],
            vec!["uv", "sync", "install", "--compile"],
            vec!["uv", "pip", "sync", "--compile"],
            vec!["uv", "pip", "install", "pkg==1"],
            vec!["uv", "pip", "install", "pkg==1", "--", "--compile"],
        ] {
            assert!(
                !requests_bytecode_compilation(&argv(&arguments)),
                "non-install or option-terminated compile-like operands must not claim bytecode authority: {arguments:?}"
            );
        }
    }

    #[test]
    fn matcher_classifies_only_uv_owned_run_compile_selectors() {
        for arguments in [
            vec!["uv", "run", "--compile-bytecode", "pkg==1"],
            vec!["uv", "run", "--compile", "pkg==1"],
            vec![
                "uv",
                "--color",
                "auto",
                "run",
                "--compile-bytecode",
                "pkg==1",
            ],
        ] {
            assert!(
                requests_bytecode_compilation(&argv(&arguments)),
                "uv-owned run selector must retain bytecode-materialization authority: {arguments:?}"
            );
        }

        for arguments in [
            vec!["uv", "run", "pkg==1", "--compile-bytecode"],
            vec!["uv", "run", "pkg==1", "--compile"],
            vec!["uv", "run", "--", "--compile-bytecode"],
            vec!["uv", "run", "--compile-bytecodex", "pkg==1"],
        ] {
            assert!(
                !requests_bytecode_compilation(&argv(&arguments)),
                "delegated or nearby compile-like argv must not be reinterpreted as uv authority: {arguments:?}"
            );
        }
    }
}
