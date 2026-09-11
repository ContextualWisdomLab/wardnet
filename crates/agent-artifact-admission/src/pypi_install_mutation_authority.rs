use crate::InstallIntent;

/// Return whether a PyPI install asks for mutation authority over an existing
/// installation that is not represented by the reviewed artifact.
pub(crate) fn requests_unapproved_pypi_install_mutation(intent: &InstallIntent) -> bool {
    let Some(executable) = intent.argv.first().map(String::as_str) else {
        return false;
    };
    let arguments = &intent.argv[1..];

    match executable {
        "pip" | "pip3" => requests_direct_pip_mutation(arguments),
        "uv" => requests_uv_pip_mutation(arguments),
        _ => false,
    }
}

fn requests_direct_pip_mutation(arguments: &[String]) -> bool {
    if !arguments
        .first()
        .is_some_and(|argument| argument == "install")
    {
        return false;
    }

    arguments.iter().skip(1).any(|argument| {
        matches_ignore_installed_option(argument) || matches_force_reinstall_option(argument)
    })
}

fn requests_uv_pip_mutation(arguments: &[String]) -> bool {
    if !arguments.first().is_some_and(|argument| argument == "pip")
        || !arguments
            .get(1)
            .is_some_and(|argument| argument == "install")
    {
        return false;
    }

    arguments
        .iter()
        .skip(2)
        .any(|argument| matches_uv_reinstall_option(argument))
}

fn matches_ignore_installed_option(argument: &str) -> bool {
    if argument == "-I" || argument == "-Iv" {
        return true;
    }

    argument.len() >= "--ignore-i".len() && "--ignore-installed".starts_with(argument)
}

fn matches_force_reinstall_option(argument: &str) -> bool {
    argument.len() >= "--fo".len() && "--force-reinstall".starts_with(argument)
}

fn matches_uv_reinstall_option(argument: &str) -> bool {
    matches!(argument, "--reinstall" | "--force-reinstall" | "--reinstall-package")
        || argument.starts_with("--reinstall-package=")
}

#[cfg(test)]
mod tests {
    use super::matches_uv_reinstall_option;

    #[test]
    fn uv_reinstall_matcher_accepts_only_documented_mutation_selectors() {
        for argument in [
            "--reinstall",
            "--force-reinstall",
            "--reinstall-package",
            "--reinstall-package=cwl-example",
        ] {
            assert!(
                matches_uv_reinstall_option(argument),
                "documented uv reinstall selector must be classified: {argument}"
            );
        }

        for argument in [
            "--reinstall-packagex",
            "--reinstallx",
            "--force-reinstallx",
            "--no-deps",
            "cwl-example==1.2.3",
        ] {
            assert!(
                !matches_uv_reinstall_option(argument),
                "unrelated or prefix-only argv must not gain reinstall semantics: {argument}"
            );
        }
    }
}
