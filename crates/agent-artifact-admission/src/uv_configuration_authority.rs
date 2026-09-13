use crate::InstallIntent;
use crate::policy::{uv_active_command_index, uv_run_owned_argument_end};

/// Return whether an approved uv install delegates package-source or trust
/// authority to caller-selected uv configuration.
pub(crate) fn requests_unapproved_uv_configuration_authority(intent: &InstallIntent) -> bool {
    let Some(executable) = intent.argv.first().map(String::as_str) else {
        return false;
    };
    if executable != "uv" {
        return false;
    }

    let arguments = &intent.argv[1..];
    let active_command_index = uv_active_command_index(arguments);
    let configuration_arguments = match active_command_index {
        Some(run_index) if arguments[run_index] == "run" => {
            &arguments[..uv_run_owned_argument_end(arguments, run_index)]
        }
        _ => arguments,
    };

    if configuration_arguments.iter().any(|argument| {
        argument == "--directory"
            || argument.starts_with("--directory=")
            || argument == "--config-file"
            || argument.starts_with("--config-file=")
    }) {
        return true;
    }

    if active_command_index.is_some_and(|index| arguments[index] == "run")
        && configuration_arguments
            .iter()
            .any(|argument| argument == "--project" || argument.starts_with("--project="))
    {
        return true;
    }

    let Some(pip_index) = active_command_index else {
        return false;
    };
    if arguments[pip_index] != "pip"
        || !arguments
            .get(pip_index + 1)
            .is_some_and(|argument| argument == "install")
    {
        return false;
    }

    arguments
        .iter()
        .skip(pip_index + 2)
        .any(|argument| argument == "--torch-backend" || argument.starts_with("--torch-backend="))
}
