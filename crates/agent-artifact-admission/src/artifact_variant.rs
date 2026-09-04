use crate::InstallIntent;

/// Return whether an OCI pull asks the client to expand or select artifact
/// identity that is not represented by the approved artifact coordinates.
pub(crate) fn requests_unapproved_oci_artifact_variant(intent: &InstallIntent) -> bool {
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
