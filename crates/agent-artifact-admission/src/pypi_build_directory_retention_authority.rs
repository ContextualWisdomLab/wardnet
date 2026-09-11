use crate::InstallIntent;

/// Return whether direct pip asks to retain build directories after the
/// installer operation rather than using pip's normal cleanup behavior.
///
/// Wardnet classifies only the caller-selected argv authority. Effective
/// temporary-directory placement, filesystem isolation, and final cleanup stay
/// owned by the quarantine runtime.
pub(crate) fn requests_unapproved_pypi_build_directory_retention(intent: &InstallIntent) -> bool {
    let Some(executable) = intent.argv.first().map(String::as_str) else {
        return false;
    };
    if !matches!(executable, "pip" | "pip3") {
        return false;
    }

    let arguments = &intent.argv[1..];
    if !arguments
        .first()
        .is_some_and(|argument| argument == "install")
    {
        return false;
    }

    arguments
        .iter()
        .skip(1)
        .any(|argument| matches_pip_no_clean_option(argument))
}

/// Direct pip uses Python optparse long-option abbreviation semantics. On the
/// pinned option surface `--no-c` is ambiguous, while `--no-cl` uniquely
/// selects canonical `--no-clean`.
fn matches_pip_no_clean_option(argument: &str) -> bool {
    argument.len() >= "--no-cl".len() && "--no-clean".starts_with(argument)
}

#[cfg(test)]
mod tests {
    use super::matches_pip_no_clean_option;

    #[test]
    fn no_clean_matcher_is_bounded_to_verified_unambiguous_prefixes() {
        for argument in ["--no-cl", "--no-cle", "--no-clea", "--no-clean"] {
            assert!(
                matches_pip_no_clean_option(argument),
                "verified direct-pip no-clean spelling must be classified: {argument}"
            );
        }

        for argument in [
            "--no-c",
            "--no-co",
            "--no-clean=false",
            "--no-cleaner",
            "--no-input",
            "--no-deps",
        ] {
            assert!(
                !matches_pip_no_clean_option(argument),
                "ambiguous, assigned, or unrelated argv must not gain no-clean semantics: {argument}"
            );
        }
    }
}
