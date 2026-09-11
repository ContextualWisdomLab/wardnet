use crate::InstallIntent;

/// Return whether direct pip-family install argv imports requirements from a
/// dependency group that is not represented by the reviewed artifact set.
pub(crate) fn requests_unapproved_pip_dependency_group(intent: &InstallIntent) -> bool {
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
        .any(|argument| requests_direct_pip_dependency_group(argument))
}

/// Direct pip uses Python's optparse-compatible long-option grammar. Pinned
/// parser verification establishes `--gro` as the shortest unambiguous prefix
/// of `--group`; shorter `--g` remains ambiguous and must not be guessed.
fn requests_direct_pip_dependency_group(argument: &str) -> bool {
    let option = argument
        .split_once('=')
        .map_or(argument, |(option, _)| option);

    option.len() >= "--gro".len() && "--group".starts_with(option)
}

#[cfg(test)]
mod tests {
    use super::requests_direct_pip_dependency_group;

    #[test]
    fn direct_pip_dependency_group_prefix_is_bounded_to_verified_language() {
        for option in [
            "--gro",
            "--gro=developer-tools",
            "--grou",
            "--grou=developer-tools",
            "--group",
            "--group=developer-tools",
        ] {
            assert!(
                requests_direct_pip_dependency_group(option),
                "verified direct-pip dependency-group spelling must be classified: {option}"
            );
        }

        for option in [
            "--g",
            "--g=developer-tools",
            "--gr",
            "--gr=developer-tools",
            "--groups",
            "--groups=developer-tools",
            "--grouped",
            "--grouped=developer-tools",
            "--config-settings=group=developer-tools",
        ] {
            assert!(
                !requests_direct_pip_dependency_group(option),
                "ambiguous or unrelated spelling must not be invented as pip --group authority: {option}"
            );
        }
    }
}
