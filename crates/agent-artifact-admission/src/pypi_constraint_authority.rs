use crate::InstallIntent;

/// Return whether a direct pip-compatible install imports dependency or build
/// selection from a constraint document that is not represented by the
/// reviewed artifact coordinates.
pub(crate) fn requests_unapproved_pypi_constraint_authority(intent: &InstallIntent) -> bool {
    let Some(executable) = intent.argv.first().map(String::as_str) else {
        return false;
    };
    let arguments = &intent.argv[1..];

    match executable {
        "pip" | "pip3"
            if arguments
                .first()
                .is_some_and(|argument| argument == "install") =>
        {
            arguments.iter().any(|argument| {
                matches_short_value_option(argument, "-c")
                    || matches_pip_long_value_option(argument, "--constraint", "--cons")
                    || matches_pip_long_value_option(
                        argument,
                        "--build-constraint",
                        "--build-c",
                    )
            })
        }
        "uv" if arguments.first().is_some_and(|argument| argument == "pip")
            && arguments
                .get(1)
                .is_some_and(|argument| argument == "install") =>
        {
            arguments.iter().any(|argument| {
                matches_short_value_option(argument, "-c")
                    || matches_long_value_option(argument, "--constraint")
                    || matches_long_value_option(argument, "--constraints")
                    || matches_short_value_option(argument, "-b")
                    || matches_long_value_option(argument, "--build-constraint")
                    || matches_long_value_option(argument, "--build-constraints")
            })
        }
        _ => false,
    }
}

/// Match pip's documented option and the shortest unambiguous prefixes accepted
/// by its optparse-compatible long-option parser for this security authority.
fn matches_pip_long_value_option(
    argument: &str,
    canonical: &str,
    shortest_accepted_prefix: &str,
) -> bool {
    let option = argument
        .split_once('=')
        .map_or(argument, |(option, _)| option);

    option == canonical
        || (option.len() >= shortest_accepted_prefix.len() && canonical.starts_with(option))
}

fn matches_long_value_option(argument: &str, option: &str) -> bool {
    argument == option
        || argument
            .strip_prefix(option)
            .is_some_and(|suffix| suffix.starts_with('='))
}

fn matches_short_value_option(argument: &str, option: &str) -> bool {
    argument == option
        || argument
            .strip_prefix(option)
            .is_some_and(|suffix| !suffix.is_empty())
}

#[cfg(test)]
mod tests {
    use super::matches_pip_long_value_option;

    #[test]
    fn pip_constraint_prefix_matcher_starts_at_verified_unambiguous_prefix() {
        for argument in [
            "--cons",
            "--const",
            "--constraint",
            "--cons=https://x.invalid/c.txt",
            "--build-c",
            "--build-const=https://x.invalid/b.txt",
            "--build-constraint",
        ] {
            let matched = if argument.starts_with("--build-") {
                matches_pip_long_value_option(argument, "--build-constraint", "--build-c")
            } else {
                matches_pip_long_value_option(argument, "--constraint", "--cons")
            };
            assert!(matched, "accepted pip constraint prefix must be classified: {argument}");
        }

        for argument in ["--con", "--build-", "--config-settings", "--constraints"] {
            assert!(
                !matches_pip_long_value_option(argument, "--constraint", "--cons")
                    && !matches_pip_long_value_option(
                        argument,
                        "--build-constraint",
                        "--build-c"
                    ),
                "ambiguous or unrelated pip option must not be classified: {argument}"
            );
        }
    }
}
