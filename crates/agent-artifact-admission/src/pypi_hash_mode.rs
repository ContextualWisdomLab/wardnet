use crate::{InstallIntent, policy::uv_active_command_index};

/// Return whether a supported PyPI install request explicitly disables the
/// hash-checking mode that Wardnet requires for reviewed artifacts.
pub(crate) fn requests_disabled_hash_requirement(intent: &InstallIntent) -> bool {
    let Some(executable) = intent.argv.first().map(String::as_str) else {
        return false;
    };
    let arguments = &intent.argv[1..];

    let install_arguments = match executable {
        "pip" | "pip3"
            if arguments
                .first()
                .is_some_and(|argument| argument == "install") =>
        {
            &arguments[1..]
        }
        "uv" => {
            let Some(pip_index) = uv_active_command_index(arguments) else {
                return false;
            };
            if arguments.get(pip_index).map(String::as_str) != Some("pip")
                || arguments.get(pip_index + 1).map(String::as_str) != Some("install")
            {
                return false;
            }
            &arguments[pip_index + 2..]
        }
        _ => return false,
    };

    install_arguments
        .iter()
        .any(|argument| argument == "--no-require-hashes")
        || (executable == "uv"
            && install_arguments
                .iter()
                .any(|argument| argument == "--no-verify-hashes"))
}
