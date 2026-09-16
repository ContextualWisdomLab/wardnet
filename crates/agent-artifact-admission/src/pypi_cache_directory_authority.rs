use crate::{InstallIntent, policy::uv_active_command_index};

/// Return whether a PyPI install asks the package manager to place cache data
/// in a caller-selected directory outside the reviewed artifact mutation contract.
pub(crate) fn requests_unapproved_pypi_cache_directory_authority(intent: &InstallIntent) -> bool {
    let Some(executable) = intent.argv.first().map(String::as_str) else {
        return false;
    };
    let arguments = &intent.argv[1..];

    match executable {
        "pip" | "pip3" => {
            arguments
                .first()
                .is_some_and(|argument| argument == "install")
                && arguments
                    .iter()
                    .skip(1)
                    .any(|argument| matches_pip_cache_directory_option(argument))
        }
        "uv" => {
            let Some(command_index) = uv_active_command_index(arguments) else {
                return false;
            };
            arguments
                .get(command_index)
                .is_some_and(|argument| argument == "pip")
                && arguments
                    .get(command_index + 1)
                    .is_some_and(|argument| argument == "install")
                && arguments[..command_index]
                    .iter()
                    .any(|argument| matches_uv_cache_directory_option(argument))
        }
        _ => false,
    }
}

/// Match only the canonical pip General Option spelling. Pre-command option
/// normalization intentionally does not inherit install-parser abbreviations
/// without separate upstream evidence for that parser phase.
pub(crate) fn matches_canonical_pip_cache_directory_option(argument: &str) -> bool {
    argument
        .split_once('=')
        .map_or(argument, |(name, _)| name)
        == "--cache-dir"
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

fn matches_uv_cache_directory_option(argument: &str) -> bool {
    argument == "--cache-dir"
        || argument
            .strip_prefix("--cache-dir=")
            .is_some_and(|value| !value.is_empty())
}
