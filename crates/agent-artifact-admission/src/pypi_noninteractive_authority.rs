use crate::InstallIntent;

/// Return whether a direct pip install would retain interactive credential
/// discovery because the reviewed invocation omitted canonical `--no-input`.
pub(crate) fn misses_required_noninteractive_mode(intent: &InstallIntent) -> bool {
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

    !arguments.iter().any(|argument| argument == "--no-input")
}
