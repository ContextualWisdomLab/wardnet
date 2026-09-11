use crate::InstallIntent;

/// Return whether an approved uv install delegates package-source or trust
/// authority to caller-selected uv configuration.
pub(crate) fn requests_unapproved_uv_configuration_authority(intent: &InstallIntent) -> bool {
    let Some(executable) = intent.argv.first().map(String::as_str) else {
        return false;
    };
    if executable != "uv" {
        return false;
    }

    let arguments = &intent.argv[1..];
    if !arguments.first().is_some_and(|argument| argument == "pip")
        || !arguments
            .get(1)
            .is_some_and(|argument| argument == "install")
    {
        return false;
    }

    arguments.iter().skip(2).any(|argument| {
        argument == "--config-file"
            || argument.starts_with("--config-file=")
            || argument == "--torch-backend"
            || argument.starts_with("--torch-backend=")
    })
}
