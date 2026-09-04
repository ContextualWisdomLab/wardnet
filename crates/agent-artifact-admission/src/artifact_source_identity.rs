use crate::InstallIntent;

/// Return whether an install operand selects an artifact source that disagrees
/// with the reviewed registry/index name and exact version coordinate.
pub(crate) fn requests_unapproved_artifact_source(intent: &InstallIntent) -> bool {
    let Some(executable) = intent.argv.first().map(String::as_str) else {
        return false;
    };
    let arguments = &intent.argv[1..];
    let supported_direct_install = match executable {
        "npm" => arguments
            .first()
            .is_some_and(|argument| matches!(argument.as_str(), "install" | "i")),
        "pnpm" | "bun" => arguments
            .first()
            .is_some_and(|argument| matches!(argument.as_str(), "add" | "install")),
        "yarn" => arguments.first().is_some_and(|argument| argument == "add"),
        "pip" | "pip3" => arguments
            .first()
            .is_some_and(|argument| argument == "install"),
        "uv" => {
            arguments.first().is_some_and(|argument| argument == "pip")
                && arguments
                    .get(1)
                    .is_some_and(|argument| argument == "install")
        }
        _ => false,
    };
    if !supported_direct_install {
        return false;
    }

    intent.artifacts.iter().any(|artifact| {
        !artifact_argument_matches_reviewed_source(
            &artifact.ecosystem,
            &artifact.name,
            &artifact.version,
            &artifact.artifact_argument,
        )
    })
}

/// Require registry/index-backed package ecosystems to encode the exact
/// reviewed name and version in the direct installer operand. This prevents a
/// policy coordinate from being paired with an npm alias/tarball/git/folder or
/// a pip direct URL/VCS/local source that has a different source authority.
pub(crate) fn artifact_argument_matches_reviewed_source(
    ecosystem: &str,
    name: &str,
    version: &str,
    artifact_argument: &str,
) -> bool {
    match ecosystem {
        "npm" => artifact_argument == format!("{name}@{version}"),
        "pypi" => artifact_argument == format!("{name}=={version}"),
        _ => true,
    }
}
