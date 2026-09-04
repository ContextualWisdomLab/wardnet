use crate::InstallIntent;

/// Return whether a Podman pull asks the caller to replace or disable the
/// registry transport or authentication trust represented by reviewed policy.
pub(crate) fn requests_unapproved_oci_transport_trust(intent: &InstallIntent) -> bool {
    let Some(executable) = intent.argv.first().map(String::as_str) else {
        return false;
    };
    if executable != "podman" {
        return false;
    }

    let arguments = &intent.argv[1..];
    if !arguments.first().is_some_and(|argument| argument == "pull") {
        return false;
    }

    arguments.iter().skip(1).any(|argument| {
        argument == "--cert-dir"
            || argument.starts_with("--cert-dir=")
            || argument == "--authfile"
            || argument.starts_with("--authfile=")
            || argument == "--creds"
            || argument.starts_with("--creds=")
            || argument
                .strip_prefix("--tls-verify=")
                .is_some_and(is_false_boolean)
    })
}

fn is_false_boolean(value: &str) -> bool {
    matches!(value.to_ascii_lowercase().as_str(), "0" | "f" | "false")
}
