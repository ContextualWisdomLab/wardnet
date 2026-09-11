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

    arguments.iter().any(|argument| {
        argument == "--group"
            || argument
                .strip_prefix("--group")
                .is_some_and(|suffix| suffix.starts_with('='))
    })
}
