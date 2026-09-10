use crate::InstallIntent;

/// Return whether a supported PyPI install request explicitly disables the
/// hash-checking mode that Wardnet requires for reviewed artifacts.
pub(crate) fn requests_disabled_hash_requirement(intent: &InstallIntent) -> bool {
    let Some(executable) = intent.argv.first().map(String::as_str) else {
        return false;
    };
    let arguments = &intent.argv[1..];

    let is_supported_install = match executable {
        "pip" | "pip3" => arguments
            .first()
            .is_some_and(|argument| argument == "install"),
        "uv" => {
            arguments.first().is_some_and(|argument| argument == "pip")
                && arguments
                    .get(1)
                    .is_some_and(|argument| argument == "install")
        }
        _ => false,
    };

    is_supported_install
        && arguments
            .iter()
            .any(|argument| argument == "--no-require-hashes")
}
