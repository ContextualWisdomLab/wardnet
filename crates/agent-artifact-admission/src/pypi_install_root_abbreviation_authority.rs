use crate::InstallIntent;

/// Return whether direct pip selects an alternate install root through the
/// verified `--target` long-option abbreviation language.
///
/// Wardnet classifies only explicit caller argv. Effective destination paths,
/// filesystem isolation, mount policy, and cleanup remain quarantine-runtime
/// authority.
pub(crate) fn requests_unapproved_pypi_target_abbreviation(intent: &InstallIntent) -> bool {
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

    arguments.iter().skip(1).any(|argument| {
        let option = argument.split_once('=').map_or(argument.as_str(), |(name, _)| name);
        matches_pip_target_option(option)
    })
}

/// Pinned pip uses Python optparse abbreviation semantics. `--ta` is the
/// shortest verified unambiguous prefix of `--target`; `--t` is deliberately
/// excluded because it is ambiguous on the reviewed option surface.
fn matches_pip_target_option(option: &str) -> bool {
    option.len() >= "--ta".len() && "--target".starts_with(option)
}

#[cfg(test)]
mod tests {
    use super::matches_pip_target_option;

    #[test]
    fn target_matcher_is_bounded_to_verified_unambiguous_prefixes() {
        for option in ["--ta", "--tar", "--targ", "--targe", "--target"] {
            assert!(
                matches_pip_target_option(option),
                "verified direct-pip target spelling must be classified: {option}"
            );
        }

        for option in ["--t", "--targeted", "--timeout", "--prefix", "-t"] {
            assert!(
                !matches_pip_target_option(option),
                "ambiguous, superstring, unrelated, or short-option grammar must stay outside the long-prefix matcher: {option}"
            );
        }
    }
}
