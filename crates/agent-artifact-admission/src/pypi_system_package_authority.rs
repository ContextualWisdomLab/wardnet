use crate::InstallIntent;

/// Return whether a direct pip install asks pip to override the
/// externally-managed-environment protection required by the reviewed intent.
pub(crate) fn requests_pypi_system_package_override(intent: &InstallIntent) -> bool {
    let Some(executable) = intent.argv.first().map(String::as_str) else {
        return false;
    };
    if !matches!(executable, "pip" | "pip3") {
        return false;
    }

    let arguments = &intent.argv[1..];
    if !arguments
        .first()
        .is_some_and(|argument| argument == "install")
    {
        return false;
    }

    arguments
        .iter()
        .skip(1)
        .any(|argument| matches_break_system_packages_option(argument))
}

/// pip uses Python optparse, which accepts an unambiguous long-option prefix.
/// At the reviewed upstream option set `--b` is ambiguous with
/// `--build-constraint`, while `--br` is the shortest accepted prefix of
/// `--break-system-packages`.
fn matches_break_system_packages_option(argument: &str) -> bool {
    matches!(
        argument,
        "--br"
            | "--bre"
            | "--brea"
            | "--break"
            | "--break-"
            | "--break-s"
            | "--break-sy"
            | "--break-sys"
            | "--break-syst"
            | "--break-syste"
            | "--break-system"
            | "--break-system-"
            | "--break-system-p"
            | "--break-system-pa"
            | "--break-system-pac"
            | "--break-system-pack"
            | "--break-system-packa"
            | "--break-system-packag"
            | "--break-system-package"
            | "--break-system-packages"
    )
}
