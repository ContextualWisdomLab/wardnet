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
                    || matches_long_value_option(argument, "--constraint")
                    || matches_long_value_option(argument, "--build-constraint")
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
