use crate::InstallIntent;

/// Return whether a pip-compatible install asks to override the
/// externally-managed-environment protection required by the reviewed intent.
pub(crate) fn requests_pypi_system_package_override(intent: &InstallIntent) -> bool {
    let Some(executable) = intent.argv.first().map(String::as_str) else {
        return false;
    };
    let arguments = &intent.argv[1..];

    match executable {
        "pip" | "pip3"
            if arguments
                .first()
                .is_some_and(|argument| argument == "install") =>
        {
            arguments
                .iter()
                .skip(1)
                .any(|argument| matches_break_system_packages_option(argument))
        }
        "uv" if arguments.first().is_some_and(|argument| argument == "pip")
            && arguments
                .get(1)
                .is_some_and(|argument| argument == "install") =>
        {
            arguments
                .iter()
                .skip(2)
                .any(|argument| matches_uv_break_system_packages_option(argument))
        }
        _ => false,
    }
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

/// uv uses clap-style exact long options for this safety boundary. Do not
/// inherit pip's optparse long-option abbreviation semantics.
fn matches_uv_break_system_packages_option(argument: &str) -> bool {
    argument == "--break-system-packages"
}

#[cfg(test)]
mod tests {
    use super::{matches_break_system_packages_option, matches_uv_break_system_packages_option};

    #[test]
    fn direct_pip_preserves_reviewed_optparse_prefix_semantics() {
        assert!(matches_break_system_packages_option("--br"));
        assert!(matches_break_system_packages_option(
            "--break-system-packages"
        ));
        assert!(!matches_break_system_packages_option("--b"));
    }

    #[test]
    fn uv_accepts_only_the_exact_documented_safety_override() {
        assert!(matches_uv_break_system_packages_option(
            "--break-system-packages"
        ));
        assert!(!matches_uv_break_system_packages_option("--br"));
        assert!(!matches_uv_break_system_packages_option(
            "--break-system-package"
        ));
        assert!(!matches_uv_break_system_packages_option(
            "--break-system-packages=true"
        ));
    }
}
