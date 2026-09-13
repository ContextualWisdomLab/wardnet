use crate::InstallIntent;

/// Return whether a direct pip install asks pip to place cache data in a
/// caller-selected directory outside the reviewed artifact mutation contract.
pub(crate) fn requests_unapproved_pypi_cache_directory_authority(intent: &InstallIntent) -> bool {
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
        .any(|argument| matches_pip_cache_directory_option(argument))
}

/// pip uses Python optparse, which accepts an unambiguous long-option prefix.
/// `--ca` is the shortest prefix of `--cache-dir` that does not collide with
/// another current `pip install` long option at the reviewed upstream commit.
fn matches_pip_cache_directory_option(argument: &str) -> bool {
    let option = argument.split_once('=').map_or(argument, |(name, _)| name);
    matches!(
        option,
        "--ca"
            | "--cac"
            | "--cach"
            | "--cache"
            | "--cache-"
            | "--cache-d"
            | "--cache-di"
            | "--cache-dir"
    )
}
