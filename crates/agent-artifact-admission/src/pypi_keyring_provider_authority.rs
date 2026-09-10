use crate::InstallIntent;

/// Return whether a direct pip install delegates credential lookup to a caller-selected provider.
pub(crate) fn requests_unapproved_pypi_keyring_provider_authority(
    intent: &InstallIntent,
) -> bool {
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
        argument == "--keyring-provider" || argument.starts_with("--keyring-provider=")
    })
}
