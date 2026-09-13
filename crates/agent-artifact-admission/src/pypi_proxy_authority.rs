use crate::InstallIntent;

/// Return whether `argument` is a reviewed direct-pip proxy selector that consumes
/// the following argv token as its value.
pub(crate) fn is_direct_pip_proxy_value_selector(argument: &str) -> bool {
    matches!(argument, "--proxy" | "--prox")
}

pub(crate) fn is_attached_direct_pip_proxy_selector(argument: &str) -> bool {
    argument
        .strip_prefix("--proxy=")
        .or_else(|| argument.strip_prefix("--prox="))
        .is_some_and(|value| !value.is_empty())
}

/// Return whether a direct pip install delegates proxy routing to caller-selected argv.
pub(crate) fn requests_unapproved_pypi_proxy_authority(intent: &InstallIntent) -> bool {
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

    arguments.iter().skip(1).any(|argument| {
        argument == "--no-proxy-env"
            || is_direct_pip_proxy_value_selector(argument)
            || is_attached_direct_pip_proxy_selector(argument)
    })
}
