use crate::InstallIntent;

/// Return whether a supported pip install request explicitly disables the
/// hash-checking mode that Wardnet requires for reviewed PyPI artifacts.
pub(crate) fn requests_disabled_hash_requirement(intent: &InstallIntent) -> bool {
    let Some(executable) = intent.argv.first().map(String::as_str) else {
        return false;
    };
    let arguments = &intent.argv[1..];

    matches!(executable, "pip" | "pip3")
        && arguments
            .first()
            .is_some_and(|argument| argument == "install")
        && arguments
            .iter()
            .any(|argument| argument == "--no-require-hashes")
}
