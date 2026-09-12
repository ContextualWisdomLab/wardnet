use crate::InstallIntent;

const PIP_CLIENT_CERT_OPTION: &str = "--client-cert";
const SHORTEST_UNAMBIGUOUS_PREFIX: &str = "--cl";

/// Return whether a direct pip install selects caller-controlled TLS client
/// credentials through pip's optparse-compatible long-option grammar.
///
/// pip parses General Options both before command selection and again on the
/// selected command's argv. Wardnet therefore classifies the reviewed
/// `--client-cert` language on either side of the `install` token instead of
/// treating pre-command placement as unrelated command syntax.
pub(crate) fn requests_unapproved_pypi_client_certificate_authority(
    intent: &InstallIntent,
) -> bool {
    let Some(executable) = intent.argv.first().map(String::as_str) else {
        return false;
    };
    if !matches!(executable, "pip" | "pip3") {
        return false;
    }

    let arguments = &intent.argv[1..];
    let Some(install_index) = arguments.iter().position(|argument| argument == "install") else {
        return false;
    };

    arguments[..install_index]
        .iter()
        .chain(arguments[install_index + 1..].iter())
        .any(|argument| matches_pip_client_certificate_option(argument))
}

/// Match only the pinned pip parser language for `--client-cert`: the exact
/// option and its verified unambiguous prefixes beginning at `--cl`.
pub(crate) fn matches_pip_client_certificate_option(argument: &str) -> bool {
    let option = argument
        .split_once('=')
        .map_or(argument, |(option, _)| option);

    option.len() >= SHORTEST_UNAMBIGUOUS_PREFIX.len() && PIP_CLIENT_CERT_OPTION.starts_with(option)
}

#[cfg(test)]
mod tests {
    use super::matches_pip_client_certificate_option;

    #[test]
    fn pip_client_certificate_prefix_matcher_is_bounded_to_verified_language() {
        for argument in [
            "--cl",
            "--cli",
            "--client",
            "--client-",
            "--client-c",
            "--client-cert",
            "--cl=/tmp/client.pem",
            "--client-cert=/tmp/client.pem",
        ] {
            assert!(
                matches_pip_client_certificate_option(argument),
                "accepted pip client-certificate prefix must be classified: {argument}"
            );
        }

        for argument in [
            "--c",
            "--cert",
            "--client-certificate",
            "--client-cert-extra",
            "--clock",
        ] {
            assert!(
                !matches_pip_client_certificate_option(argument),
                "ambiguous or unrelated option must not be classified: {argument}"
            );
        }
    }
}
