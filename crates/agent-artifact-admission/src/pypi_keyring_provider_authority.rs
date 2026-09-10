use crate::InstallIntent;

/// Return whether a direct pip install delegates credential lookup to a caller-selected provider.
pub(crate) fn requests_unapproved_pypi_keyring_provider_authority(intent: &InstallIntent) -> bool {
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
        .enumerate()
        .skip(1)
        .any(|(index, argument)| {
            let (option, attached_value) = argument
                .split_once('=')
                .map_or((argument.as_str(), None), |(flag, value)| {
                    (flag, Some(value))
                });
            if !is_keyring_provider_option(option) {
                return false;
            }

            attached_value
                .or_else(|| arguments.get(index + 1).map(String::as_str))
                .is_some_and(expands_keyring_authority)
        })
}

fn is_keyring_provider_option(argument: &str) -> bool {
    argument.starts_with("--k") && "--keyring-provider".starts_with(argument)
}

fn expands_keyring_authority(provider: &str) -> bool {
    matches!(provider, "import" | "subprocess")
}
