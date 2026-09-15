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

    arguments
        .iter()
        .skip(1)
        .any(|argument| matches_pip_log_option(argument))
}

/// pip uses Python optparse, which accepts unambiguous long-option prefixes.
/// Keep this accepted-language set explicit so an ambiguous prefix such as
/// `--lo` is not reinterpreted by Wardnet as valid caller authority.
fn matches_pip_log_option(argument: &str) -> bool {
    let option = argument.split_once('=').map_or(argument, |(name, _)| name);
    matches!(
        option,
        "--log"
            | "--log-"
            | "--log-f"
            | "--log-fi"
            | "--log-fil"
            | "--log-file"
            | "--loc"
            | "--loca"
            | "--local"
            | "--local-"
            | "--local-l"
            | "--local-lo"
            | "--local-log"
    )
}
