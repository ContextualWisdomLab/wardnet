use crate::InstallIntent;

/// Return whether `argument` is a reviewed direct-pip proxy selector that consumes
/// the following argv token as its value.
pub(crate) fn is_direct_pip_proxy_value_selector(argument: &str) -> bool {
    matches!(argument, "--proxy" | "--prox")
}

fn is_attached_direct_pip_proxy_selector(argument: &str) -> bool {
    argument
        .strip_prefix("--proxy=")
        .or_else(|| argument.strip_prefix("--prox="))
        .is_some_and(|value| !value.is_empty())
}

/// Canonicalize only the reviewed pip global-proxy grammar for policy evaluation.
///
/// pip accepts `--proxy` as a General Option before the `install` command. Wardnet
/// keeps the submitted argv unchanged for audit evidence, but evaluates this bounded
/// parser-valid spelling as the equivalent `install --proxy ...` form so the existing
/// install policy can classify proxy authority without treating its value as a package.
/// Any unreviewed pre-command token fails closed and is left untouched.
pub(crate) fn normalize_direct_pip_global_proxy_intent(
    intent: &InstallIntent,
) -> Option<InstallIntent> {
    let executable = intent.argv.first()?.as_str();
    if !matches!(executable, "pip" | "pip3") {
        return None;
    }

    let arguments = &intent.argv[1..];
    if arguments
        .first()
        .is_some_and(|argument| argument == "install")
    {
        return None;
    }

    let mut index = 0;
    let mut global_proxy_arguments = Vec::new();
    while index < arguments.len() {
        let argument = arguments[index].as_str();
        if argument == "install" {
            if global_proxy_arguments.is_empty() {
                return None;
            }

            let mut normalized = intent.clone();
            let mut argv = Vec::with_capacity(intent.argv.len());
            argv.push(executable.to_string());
            argv.push("install".to_string());
            argv.extend(global_proxy_arguments);
            argv.extend(arguments[index + 1..].iter().cloned());
            normalized.argv = argv;
            return Some(normalized);
        }

        if is_direct_pip_proxy_value_selector(argument) {
            let value = arguments.get(index + 1)?;
            if value == "install" || value.starts_with('-') || value.is_empty() {
                return None;
            }
            global_proxy_arguments.push(arguments[index].clone());
            global_proxy_arguments.push(value.clone());
            index += 2;
            continue;
        }

        if is_attached_direct_pip_proxy_selector(argument) {
            global_proxy_arguments.push(arguments[index].clone());
            index += 1;
            continue;
        }

        return None;
    }

    None
}

/// Return whether a direct pip install delegates proxy routing to caller-selected argv.
pub(crate) fn requests_unapproved_pypi_proxy_authority(intent: &InstallIntent) -> bool {
    let Some(executable) = intent.argv.first().map(String::as_str) else {
        return false;
    };
    if !matches!(executable, "pip" | "pip3") {
        return false;
    }

    if normalize_direct_pip_global_proxy_intent(intent).is_some() {
        return true;
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
