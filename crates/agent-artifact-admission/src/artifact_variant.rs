use crate::InstallIntent;

/// Return whether an OCI pull asks the client to expand or select artifact
/// identity that is not represented by the approved artifact coordinates.
pub(crate) fn requests_unapproved_oci_artifact_variant(intent: &InstallIntent) -> bool {
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

    arguments.iter().any(|argument| {
        argument == "--all-tags"
            || argument == "-a"
            || argument == "--platform"
            || argument.starts_with("--platform=")
            || (executable == "podman"
                && (argument == "--arch"
                    || argument.starts_with("--arch=")
                    || argument == "--os"
                    || argument.starts_with("--os=")
                    || argument == "--variant"
                    || argument.starts_with("--variant=")))
    })
}
