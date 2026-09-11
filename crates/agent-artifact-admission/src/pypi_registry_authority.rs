use crate::InstallIntent;

/// Return whether a direct Python package install disables the exact reviewed
/// registry and can therefore inherit a different package-source authority.
pub(crate) fn disables_reviewed_registry(intent: &InstallIntent) -> bool {
    let Some(executable) = intent.argv.first().map(String::as_str) else {
        return false;
    };
    let arguments = &intent.argv[1..];
    let is_direct_pypi_install = match executable {
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
    if !is_direct_pypi_install {
        return false;
    }

    arguments.iter().any(|argument| argument == "--no-index")
}
