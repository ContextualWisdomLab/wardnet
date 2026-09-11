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

    if matches!(executable, "pip" | "pip3")
        && arguments
            .iter()
            .skip(1)
            .any(|argument| requests_pip_indirect_source_abbreviation(argument))
    {
        return true;
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

/// Direct pip uses Python's optparse-compatible parser, which accepts
/// unambiguous long-option prefixes. Canonical `--requirement`/`--editable`
/// and their short spellings are already rejected by the policy evaluator;
/// this source-identity boundary covers only the accepted long abbreviations
/// that otherwise introduce an undeclared requirements or editable source.
fn requests_pip_indirect_source_abbreviation(argument: &str) -> bool {
    let option = argument
        .split_once('=')
        .map_or(argument, |(option, _)| option);

    [
        ("--requirement", "--requirem"),
        ("--editable", "--ed"),
    ]
    .iter()
    .any(|(canonical, shortest_accepted_prefix)| {
        option.len() >= shortest_accepted_prefix.len()
            && option != *canonical
            && canonical.starts_with(option)
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

#[cfg(test)]
mod tests {
    use super::requests_pip_indirect_source_abbreviation;

    #[test]
    fn pip_indirect_source_abbreviations_are_bounded_to_verified_prefixes() {
        for option in [
            "--requirem=attacker-requirements.txt",
            "--requireme",
            "--ed=git+https://attacker.invalid/example.git",
            "--edit",
        ] {
            assert!(
                requests_pip_indirect_source_abbreviation(option),
                "accepted pip indirect-source abbreviation must be classified: {option}"
            );
        }

        for option in [
            "--requ=attacker-requirements.txt",
            "--e=git+https://attacker.invalid/example.git",
            "--requirement=attacker-requirements.txt",
            "--editable=git+https://attacker.invalid/example.git",
            "--extra-index-url=https://attacker.invalid/simple",
        ] {
            assert!(
                !requests_pip_indirect_source_abbreviation(option),
                "ambiguous, canonical, or unrelated option must not be classified as a pip abbreviation: {option}"
            );
        }
    }
}
