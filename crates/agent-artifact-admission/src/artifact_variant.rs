use crate::InstallIntent;

/// Return whether an OCI pull asks the client to select a platform variant that
/// is not represented by the approved artifact coordinate.
pub(crate) fn requests_unapproved_oci_platform(intent: &InstallIntent) -> bool {
    let Some(executable) = intent.argv.first().map(String::as_str) else {
        return false;
    };
    if !matches!(executable, "docker" | "podman") {
        return false;
    }

    let arguments = &intent.argv[1..];
    if !arguments.first().is_some_and(|argument| argument == "pull") {
        return false;
    }

    arguments
        .iter()
        .any(|argument| argument == "--platform" || argument.starts_with("--platform="))
}
