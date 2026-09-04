use crate::InstallIntent;

/// Return whether a supported PyPI install can resolve dependencies that are
/// absent from the reviewed artifact set.
pub(crate) fn misses_exact_dependency_set_guard(intent: &InstallIntent) -> bool {
    let Some(executable) = intent.argv.first().map(String::as_str) else {
        return false;
    };
    let arguments = &intent.argv[1..];

    let is_pypi_install = match executable {
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

    is_pypi_install && !arguments.iter().any(|argument| argument == "--no-deps")
}
