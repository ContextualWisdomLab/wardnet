use crate::InstallIntent;

const PIP_VALUE_SOURCE_SELECTORS: [(&str, &str); 3] = [
    ("--index-url", "--in"),
    ("--extra-index-url", "--ext"),
    ("--find-links", "--fi"),
];
const PIP_NO_INDEX_CANONICAL: &str = "--no-index";
const PIP_NO_INDEX_SHORTEST_ACCEPTED_PREFIX: &str = "--no-ind";
const PIP_TRUSTED_HOST_CANONICAL: &str = "--trusted-host";
const PIP_TRUSTED_HOST_SHORTEST_ACCEPTED_PREFIX: &str = "--tr";

/// Return whether a direct Python package install disables or replaces the exact
/// reviewed registry/source authority or relaxes its reviewed transport trust.
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
        argument == PIP_NO_INDEX_CANONICAL
            || (matches!(executable, "pip" | "pip3")
                && (requests_pip_source_selector_abbreviation(argument)
                    || requests_pip_trusted_host_abbreviation(argument)))
    })
}

/// Return whether `argument` is a reviewed direct-pip registry/source selector
/// that consumes one value. This is the shared language for both post-command
/// policy evaluation and the bounded pre-command General Option normalizer.
pub(crate) fn is_reviewed_pip_registry_value_selector(argument: &str) -> bool {
    let option = option_name(argument);

    PIP_VALUE_SOURCE_SELECTORS
        .iter()
        .any(|(canonical, shortest_accepted_prefix)| {
            option == *canonical
                || is_unambiguous_long_option_prefix(option, canonical, shortest_accepted_prefix)
        })
        || option == PIP_TRUSTED_HOST_CANONICAL
        || is_unambiguous_long_option_prefix(
            option,
            PIP_TRUSTED_HOST_CANONICAL,
            PIP_TRUSTED_HOST_SHORTEST_ACCEPTED_PREFIX,
        )
}

/// Return whether `argument` is the reviewed value-less `--no-index` selector
/// or one of pip's verified unambiguous long-option prefixes for it.
pub(crate) fn is_reviewed_pip_no_index_selector(argument: &str) -> bool {
    if argument.contains('=') {
        return false;
    }

    let option = option_name(argument);
    option == PIP_NO_INDEX_CANONICAL
        || is_unambiguous_long_option_prefix(
            option,
            PIP_NO_INDEX_CANONICAL,
            PIP_NO_INDEX_SHORTEST_ACCEPTED_PREFIX,
        )
}

/// pip's optparse-compatible CLI accepts unambiguous long-option prefixes. The
/// generic argv guard intentionally matches exact option names because other
/// installers do not share that grammar, so pip source selectors need their
/// accepted prefix forms classified here as the same trust-root authority.
fn requests_pip_source_selector_abbreviation(argument: &str) -> bool {
    let option = option_name(argument);

    PIP_VALUE_SOURCE_SELECTORS
        .iter()
        .any(|(canonical, shortest_accepted_prefix)| {
            is_unambiguous_long_option_prefix(option, canonical, shortest_accepted_prefix)
        })
        || is_unambiguous_long_option_prefix(
            option,
            PIP_NO_INDEX_CANONICAL,
            PIP_NO_INDEX_SHORTEST_ACCEPTED_PREFIX,
        )
}

/// Direct pip also accepts unambiguous prefixes of `--trusted-host`. `--tr` is
/// the shortest verified prefix while `--t` remains ambiguous with other pip
/// options. Classify only the accepted direct-pip abbreviation language here;
/// canonical `--trusted-host` remains covered by the generic exact-option guard.
fn requests_pip_trusted_host_abbreviation(argument: &str) -> bool {
    is_unambiguous_long_option_prefix(
        option_name(argument),
        PIP_TRUSTED_HOST_CANONICAL,
        PIP_TRUSTED_HOST_SHORTEST_ACCEPTED_PREFIX,
    )
}

fn option_name(argument: &str) -> &str {
    argument
        .split_once('=')
        .map_or(argument, |(option, _)| option)
}

fn is_unambiguous_long_option_prefix(
    option: &str,
    canonical: &str,
    shortest_accepted_prefix: &str,
) -> bool {
    option.len() >= shortest_accepted_prefix.len()
        && option != canonical
        && canonical.starts_with(option)
}

#[cfg(test)]
mod tests {
    use super::{
        is_reviewed_pip_no_index_selector, is_reviewed_pip_registry_value_selector,
        requests_pip_source_selector_abbreviation, requests_pip_trusted_host_abbreviation,
    };

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

    #[test]
    fn pip_trusted_host_abbreviations_are_bounded_to_verified_prefixes() {
        for option in [
            "--tr=attacker.invalid",
            "--tru=attacker.invalid",
            "--trusted-h=attacker.invalid",
        ] {
            assert!(
                requests_pip_trusted_host_abbreviation(option),
                "accepted pip trusted-host abbreviation must be classified: {option}"
            );
        }

        for option in [
            "--t=attacker.invalid",
            "--trusted-host=attacker.invalid",
            "--trusted-host-extra=attacker.invalid",
            "--timeout=10",
        ] {
            assert!(
                !requests_pip_trusted_host_abbreviation(option),
                "ambiguous, canonical, or unrelated option must not be classified as a pip abbreviation: {option}"
            );
        }
    }

    #[test]
    fn reviewed_global_registry_value_selectors_share_the_verified_language() {
        for option in [
            "--index-url",
            "--in",
            "--extra-index-url",
            "--ext",
            "--find-links",
            "--fi",
            "--trusted-host",
            "--tr",
        ] {
            assert!(is_reviewed_pip_registry_value_selector(option));
        }

        for option in ["--i", "--ex", "--f", "--t", "--no-index", "--no-ind"] {
            assert!(!is_reviewed_pip_registry_value_selector(option));
        }
    }

    #[test]
    fn reviewed_global_no_index_selector_is_value_less_and_bounded() {
        for option in ["--no-index", "--no-ind", "--no-inde"] {
            assert!(is_reviewed_pip_no_index_selector(option));
        }

        for option in ["--no-i", "--no-index=value", "--no-ind=value", "--no-deps"] {
            assert!(!is_reviewed_pip_no_index_selector(option));
        }
    }
}
