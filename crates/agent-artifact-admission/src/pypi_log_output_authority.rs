use crate::InstallIntent;

/// Return whether a direct pip install asks the client to append verbose logs
/// to a caller-selected filesystem path outside the reviewed install intent.
pub(crate) fn requests_unapproved_pypi_log_output_authority(intent: &InstallIntent) -> bool {
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
        matches_path_option(argument, "--log")
            || matches_path_option(argument, "--log-file")
            || matches_path_option(argument, "--local-log")
    })
}

fn matches_path_option(argument: &str, option: &str) -> bool {
    argument == option
        || argument
            .strip_prefix(option)
            .is_some_and(|suffix| suffix.starts_with('='))
}
