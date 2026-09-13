use crate::{InstallIntent, policy::uv_active_command_index};

/// Return whether a supported PyPI install can resolve dependencies that are
/// absent from the reviewed artifact set.
pub(crate) fn misses_exact_dependency_set_guard(intent: &InstallIntent) -> bool {
    let Some(executable) = intent.argv.first().map(String::as_str) else {
        return false;
    };
    let arguments = &intent.argv[1..];

    match executable {
        "pip" | "pip3" => {
            arguments
                .first()
                .is_some_and(|argument| argument == "install")
                && !arguments.iter().any(|argument| argument == "--no-deps")
        }
        "uv" => {
            let Some(pip_index) = uv_active_command_index(arguments) else {
                return false;
            };
            arguments.get(pip_index).map(String::as_str) == Some("pip")
                && arguments.get(pip_index + 1).map(String::as_str) == Some("install")
                && !arguments[pip_index + 2..]
                    .iter()
                    .any(|argument| argument == "--no-deps")
        }
        _ => false,
    }
}

/// Return whether the currently supported npm-family direct-install grammar can
/// widen one reviewed direct artifact into resolver-selected transitive artifacts.
///
/// npm, pnpm, Yarn, and Bun all resolve dependency closures for direct package
/// installs. The v0.1 policy binds only direct artifact operands and therefore
/// has no trustworthy way to prove the exact transitive closure those commands
/// will materialize. Until a reviewed lockfile/material-set contract is carried
/// by the intent and enforced by the execution broker, these direct resolver
/// paths must fail closed rather than treating `--ignore-scripts` as dependency
/// identity control.
pub(crate) fn npm_family_dependency_closure_is_unverified(intent: &InstallIntent) -> bool {
    let Some(executable) = intent.argv.first().map(String::as_str) else {
        return false;
    };
    let arguments = &intent.argv[1..];

    match executable {
        "npm" => arguments
            .first()
            .is_some_and(|argument| matches!(argument.as_str(), "install" | "i")),
        "pnpm" | "bun" => arguments
            .first()
            .is_some_and(|argument| matches!(argument.as_str(), "add" | "install")),
        "yarn" => arguments.first().is_some_and(|argument| argument == "add"),
        _ => false,
    }
}
