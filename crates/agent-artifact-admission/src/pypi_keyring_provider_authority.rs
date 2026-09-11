use crate::InstallIntent;

/// Return whether a supported PyPI installer delegates credential lookup to a caller-selected provider.
pub(crate) fn requests_unapproved_pypi_keyring_provider_authority(intent: &InstallIntent) -> bool {
    let Some(executable) = intent.argv.first().map(String::as_str) else {
        return false;
    };
    let arguments = &intent.argv[1..];

    let (provider_arguments, pip_compatible_abbreviation, non_disabled_provider_expands_authority) =
        match executable {
            "pip" | "pip3"
                if arguments
                    .first()
                    .is_some_and(|argument| argument == "install") =>
            {
                (&arguments[1..], true, false)
            }
            "uv" if arguments.first().is_some_and(|argument| argument == "pip")
                && arguments
                    .get(1)
                    .is_some_and(|argument| argument == "install") =>
            {
                (&arguments[2..], false, true)
            }
            _ => return false,
        };

    provider_arguments
        .iter()
        .enumerate()
        .any(|(index, argument)| {
            let (option, attached_value) = argument
                .split_once('=')
                .map_or((argument.as_str(), None), |(flag, value)| {
                    (flag, Some(value))
                });
            if !is_keyring_provider_option(option, pip_compatible_abbreviation) {
                return false;
            }

            attached_value
                .or_else(|| provider_arguments.get(index + 1).map(String::as_str))
                .is_some_and(|provider| {
                    if non_disabled_provider_expands_authority {
                        provider != "disabled"
                    } else {
                        provider == "subprocess" || provider == "import"
                    }
                })
        })
}

fn is_keyring_provider_option(argument: &str, pip_compatible_abbreviation: bool) -> bool {
    if pip_compatible_abbreviation {
        argument.starts_with("--k") && "--keyring-provider".starts_with(argument)
    } else {
        argument == "--keyring-provider"
    }
}
