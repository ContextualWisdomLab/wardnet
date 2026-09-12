use crate::InstallIntent;

/// Return whether an approved `uv pip install` asks uv to eagerly generate
/// interpreter-dependent bytecode that is outside the reviewed artifact identity.
pub(crate) fn requests_unapproved_uv_bytecode_compilation(intent: &InstallIntent) -> bool {
    requests_bytecode_compilation(&intent.argv)
}

fn requests_bytecode_compilation(argv: &[String]) -> bool {
    let [executable, subcommand, command, arguments @ ..] = argv else {
        return false;
    };
    if executable != "uv" || subcommand != "pip" || command != "install" {
        return false;
    }

    arguments
        .iter()
        .take_while(|argument| argument.as_str() != "--")
        .any(|argument| matches!(argument.as_str(), "--compile-bytecode" | "--compile"))
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
    fn matcher_is_bounded_to_uv_pip_install_and_option_phase() {
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
}
