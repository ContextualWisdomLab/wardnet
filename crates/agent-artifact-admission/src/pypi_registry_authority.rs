use crate::InstallIntent;

/// Return whether a direct Python package install disables or replaces the exact
/// reviewed registry/source authority.
pub(crate) fn disables_reviewed_registry(intent: &InstallIntent) -> bool {
    let Some(executable) = intent.argv.first().map(String::as_str) else {
        return false;
    };
    let arguments = &intent.argv[1..];
    let is_direct_pypi_install = match executable {
        "pip" | "pip3" => arguments
            .first()
            .is_some_and(|argument| argument == "install"),
        "uv" => {
            arguments.first().is_some_and(|argument| argument == "pip")
                && arguments
                    .get(1)
                    .is_some_and(|argument| argument == "install")
        }
        _ => false,
    };
    if !is_direct_pypi_install {
        return false;
    }

    arguments.iter().any(|argument| {
        argument == "--no-index"
            || (matches!(executable, "pip" | "pip3")
                && requests_pip_source_selector_abbreviation(argument))
    })
}

/// pip's optparse-compatible CLI accepts unambiguous long-option prefixes. The
/// generic argv guard intentionally matches exact option names because other
/// installers do not share that grammar, so pip source selectors need their
/// accepted prefix forms classified here as the same trust-root authority.
fn requests_pip_source_selector_abbreviation(argument: &str) -> bool {
    let option = argument
        .split_once('=')
        .map_or(argument, |(option, _)| option);

    [
        ("--index-url", "--in"),
        ("--extra-index-url", "--ext"),
        ("--find-links", "--fi"),
        ("--no-index", "--no-ind"),
    ]
    .iter()
    .any(|(canonical, shortest_accepted_prefix)| {
        option.len() >= shortest_accepted_prefix.len()
            && option != *canonical
            && canonical.starts_with(option)
    })
}

#[cfg(test)]
mod tests {
    use super::requests_pip_source_selector_abbreviation;

    #[test]
    fn pip_source_selector_abbreviations_are_bounded_to_accepted_prefixes() {
        for option in [
            "--in=https://attacker.invalid/simple",
            "--index-u=https://attacker.invalid/simple",
            "--ext=https://attacker.invalid/simple",
            "--extra-index-u=https://attacker.invalid/simple",
            "--fi=https://attacker.invalid/simple",
            "--find-l=https://attacker.invalid/simple",
            "--no-ind",
        ] {
            assert!(
                requests_pip_source_selector_abbreviation(option),
                "accepted pip source-selector abbreviation must be classified: {option}"
            );
        }

        for option in [
            "--i=https://attacker.invalid/simple",
            "--ex=https://attacker.invalid/simple",
            "--f=https://attacker.invalid/simple",
            "--no-i",
            "--index-url=https://attacker.invalid/simple",
            "--extra-index-url=https://attacker.invalid/simple",
            "--find-links=https://attacker.invalid/simple",
            "--no-index",
            "--no-deps",
        ] {
            assert!(
                !requests_pip_source_selector_abbreviation(option),
                "ambiguous, full, or unrelated option must not be classified as a pip abbreviation: {option}"
            );
        }
    }
}
