use crate::InstallIntent;

/// Return whether a PyPI install asks for mutation authority over an existing
/// installation that is not represented by the reviewed artifact.
pub(crate) fn requests_unapproved_pypi_install_mutation(intent: &InstallIntent) -> bool {
    let Some(executable) = intent.argv.first().map(String::as_str) else {
        return false;
    };
    let arguments = &intent.argv[1..];

    match executable {
        "pip" | "pip3" => requests_direct_pip_mutation(arguments),
        "uv" => requests_uv_pip_mutation(arguments),
        _ => false,
    }
}

fn requests_direct_pip_mutation(arguments: &[String]) -> bool {
    if !arguments
        .first()
        .is_some_and(|argument| argument == "install")
    {
        return false;
    }

    arguments.iter().skip(1).any(|argument| {
        matches_ignore_installed_option(argument)
            || matches_force_reinstall_option(argument)
            || matches_upgrade_option(argument)
    })
}

fn requests_uv_pip_mutation(arguments: &[String]) -> bool {
    if !arguments.first().is_some_and(|argument| argument == "pip")
        || !arguments
            .get(1)
            .is_some_and(|argument| argument == "install")
    {
        return false;
    }

    arguments
        .iter()
        .skip(2)
        .any(|argument| matches_uv_install_mutation_option(argument))
}

fn matches_ignore_installed_option(argument: &str) -> bool {
    matches_pip_no_value_short_cluster(argument, b'I')
        || (argument.len() >= "--ignore-i".len() && "--ignore-installed".starts_with(argument))
}

fn matches_force_reinstall_option(argument: &str) -> bool {
    argument.len() >= "--fo".len() && "--force-reinstall".starts_with(argument)
}

fn matches_upgrade_option(argument: &str) -> bool {
    matches_pip_no_value_short_cluster(argument, b'U') || argument == "--upgrade"
}

/// Classify only the reviewed direct-pip no-value short-option cluster grammar.
///
/// `pip` inherits `optparse` clustering for no-value `-v`, `-q`, `-I`, and `-U`
/// selectors. Value-taking or unknown short options are deliberately excluded so
/// their remaining bytes cannot be misclassified as embedded mutation authority.
fn matches_pip_no_value_short_cluster(argument: &str, required_flag: u8) -> bool {
    let Some(cluster) = argument.strip_prefix('-') else {
        return false;
    };
    let bytes = cluster.as_bytes();
    !bytes.is_empty()
        && bytes
            .iter()
            .all(|byte| matches!(*byte, b'v' | b'q' | b'I' | b'U'))
        && bytes.contains(&required_flag)
}

fn matches_uv_install_mutation_option(argument: &str) -> bool {
    matches!(
        argument,
        "--exact" | "--reinstall" | "--force-reinstall" | "--reinstall-package"
    ) || argument.starts_with("--reinstall-package=")
}

#[cfg(test)]
mod tests {
    use super::{
        matches_ignore_installed_option, matches_upgrade_option, matches_uv_install_mutation_option,
    };

    #[test]
    fn direct_pip_ignore_installed_matcher_accepts_only_reviewed_mutation_selectors() {
        for argument in [
            "-I",
            "-Iv",
            "-Ivv",
            "-vI",
            "-qI",
            "-IU",
            "-UI",
            "--ignore-i",
            "--ignore-installed",
        ] {
            assert!(
                matches_ignore_installed_option(argument),
                "reviewed pip ignore-installed selector must be classified: {argument}"
            );
        }

        for argument in [
            "-",
            "-v",
            "-q",
            "-U",
            "-iI",
            "-rI",
            "-tI",
            "-Ixyz",
            "-u",
            "--ignore",
            "--ignore-installedx",
            "cwl-example==1.2.3",
        ] {
            assert!(
                !matches_ignore_installed_option(argument),
                "value-taking, malformed, or unrelated argv must not inherit ignore-installed semantics: {argument}"
            );
        }
    }

    #[test]
    fn direct_pip_upgrade_matcher_accepts_only_reviewed_mutation_selectors() {
        for argument in ["-U", "-Uv", "-Uvv", "-vU", "-qU", "-IU", "-UI", "--upgrade"] {
            assert!(
                matches_upgrade_option(argument),
                "reviewed pip upgrade selector must be classified: {argument}"
            );
        }

        for argument in [
            "-",
            "-v",
            "-q",
            "-I",
            "-iU",
            "-rU",
            "-tU",
            "-Uxyz",
            "--upgrade-strategy=eager",
            "--upgrade-strategy",
            "--up",
            "--upgrades",
            "-u",
            "--no-deps",
            "cwl-example==1.2.3",
        ] {
            assert!(
                !matches_upgrade_option(argument),
                "distinct or unreviewed argv must not inherit upgrade semantics: {argument}"
            );
        }
    }

    #[test]
    fn uv_install_mutation_matcher_accepts_only_documented_mutation_selectors() {
        for argument in [
            "--exact",
            "--reinstall",
            "--force-reinstall",
            "--reinstall-package",
            "--reinstall-package=cwl-example",
        ] {
            assert!(
                matches_uv_install_mutation_option(argument),
                "documented uv install-mutation selector must be classified: {argument}"
            );
        }

        for argument in [
            "--exact=true",
            "--reinstall-packagex",
            "--reinstallx",
            "--force-reinstallx",
            "--no-deps",
            "cwl-example==1.2.3",
        ] {
            assert!(
                !matches_uv_install_mutation_option(argument),
                "unrelated or unsupported argv must not gain install-mutation semantics: {argument}"
            );
        }
    }
}
