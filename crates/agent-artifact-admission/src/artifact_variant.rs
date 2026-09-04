use crate::InstallIntent;

/// Return whether an install asks the package client to expand or select
/// artifact/build identity that is not represented by the approved coordinates.
pub(crate) fn requests_unapproved_artifact_variant(intent: &InstallIntent) -> bool {
    requests_unapproved_oci_artifact_variant(intent)
        || requests_unapproved_pypi_artifact_variant(intent)
}

/// Return whether an OCI pull asks the client to expand or select artifact
/// identity that is not represented by the approved artifact coordinates.
fn requests_unapproved_oci_artifact_variant(intent: &InstallIntent) -> bool {
    let Some(executable) = intent.argv.first().map(String::as_str) else {
        return false;
    };
    if !matches!(executable, "docker" | "podman") {
        return false;
    }

    let arguments = &intent.argv[1..];
    if !arguments.first().is_some_and(|argument| argument == "pull") {
        return false;
    }

    arguments.iter().any(|argument| {
        argument == "--all-tags"
            || argument == "-a"
            || requests_all_tags_short_bundle(argument)
            || argument
                .strip_prefix("--all-tags=")
                .is_some_and(is_true_boolean)
            || argument.strip_prefix("-a=").is_some_and(is_true_boolean)
            || argument == "--platform"
            || argument.starts_with("--platform=")
            || (executable == "podman"
                && (argument == "--arch"
                    || argument.starts_with("--arch=")
                    || argument == "--os"
                    || argument.starts_with("--os=")
                    || argument == "--variant"
                    || argument.starts_with("--variant=")))
    })
}

/// Pip can select a wheel compatibility target or force/configure a source
/// build independently of the name/version coordinate. Until policy carries
/// that artifact/build identity, caller-selected selectors fail closed.
fn requests_unapproved_pypi_artifact_variant(intent: &InstallIntent) -> bool {
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
        matches_value_flag(argument, "--platform")
            || matches_value_flag(argument, "--python-version")
            || matches_value_flag(argument, "--implementation")
            || matches_value_flag(argument, "--abi")
            || matches_value_flag(argument, "--no-binary")
            || matches_value_flag(argument, "--only-binary")
            || argument == "--prefer-binary"
            || argument == "--no-build-isolation"
            || matches_short_value_flag(argument, "-C")
            || matches_value_flag(argument, "--config-settings")
    })
}

fn matches_value_flag(argument: &str, flag: &str) -> bool {
    argument == flag || argument.strip_prefix(flag).is_some_and(|suffix| suffix.starts_with('='))
}

/// Pip's option parser accepts short options with their required value attached,
/// for example `-Cbackend-mode=unsafe`, so exact-token matching is insufficient.
fn matches_short_value_flag(argument: &str, flag: &str) -> bool {
    argument == flag
        || argument
            .strip_prefix(flag)
            .is_some_and(|suffix| !suffix.is_empty())
}

/// Docker and Podman expose `-a` (`--all-tags`) and `-q` (`--quiet`) as
/// Boolean pull shorthands. Their pflag-style parsers permit shorthand bundles;
/// every non-final Boolean shorthand is enabled while an attached assignment
/// belongs to the final shorthand. Thus `-aq=false` still enables `-a`, whereas
/// `-qa=false` leaves `-a` disabled.
fn requests_all_tags_short_bundle(argument: &str) -> bool {
    let Some(bundle) = argument.strip_prefix('-') else {
        return false;
    };
    if bundle.starts_with('-') {
        return false;
    }

    let (shorthands, assigned_value) = match bundle.split_once('=') {
        Some(parts) => parts,
        None => (bundle, ""),
    };
    if shorthands.chars().count() < 2
        || !shorthands.chars().all(|flag| matches!(flag, 'a' | 'q'))
    {
        return false;
    }

    let mut flags = shorthands.chars();
    let Some(last_flag) = flags.next_back() else {
        return false;
    };
    if flags.any(|flag| flag == 'a') {
        return true;
    }

    last_flag == 'a' && (assigned_value.is_empty() || is_true_boolean(assigned_value))
}

fn is_true_boolean(value: &str) -> bool {
    matches!(
        value.to_ascii_lowercase().as_str(),
        "1" | "t" | "true"
    )
}
