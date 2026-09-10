use crate::InstallIntent;

/// Return whether a pip install asks the caller to select a TLS client
/// credential outside the reviewed package and manifest authority.
pub(crate) fn requests_client_certificate_override(intent: &InstallIntent) -> bool {
    let Some(executable) = intent.argv.first().map(String::as_str) else {
        return false;
    };
    if !matches!(executable, "pip" | "pip3") {
        return false;
    }

    let arguments = &intent.argv[1..];
    arguments
        .first()
        .is_some_and(|argument| argument == "install")
        && arguments.iter().any(|argument| {
            argument == "--client-cert" || argument.starts_with("--client-cert=")
        })
}
