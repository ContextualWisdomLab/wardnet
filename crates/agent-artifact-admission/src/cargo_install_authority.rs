use crate::InstallIntent;

/// Return whether a Cargo install asks for mutation authority that is not
/// represented by the reviewed artifact coordinate.
pub(crate) fn requests_unapproved_cargo_install_mutation(intent: &InstallIntent) -> bool {
    let Some(executable) = intent.argv.first().map(String::as_str) else {
        return false;
    };
    if executable != "cargo"
        || !intent
            .argv
            .get(1)
            .is_some_and(|argument| argument == "install")
    {
        return false;
    }

    intent.argv.iter().skip(2).any(|argument| {
        matches_cli_flag(argument, "-f")
            || matches_cli_flag(argument, "--force")
            || matches_cli_flag(argument, "--no-track")
    })
}

fn matches_cli_flag(argument: &str, flag: &str) -> bool {
    if argument == flag {
        return true;
    }
    let Some(suffix) = argument.strip_prefix(flag) else {
        return false;
    };
    suffix.starts_with('=') || (is_short_cli_flag(flag) && !suffix.is_empty())
}

fn is_short_cli_flag(flag: &str) -> bool {
    let bytes = flag.as_bytes();
    bytes.len() == 2 && bytes[0] == b'-' && bytes[1] != b'-'
}
