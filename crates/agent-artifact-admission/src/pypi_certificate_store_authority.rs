use crate::InstallIntent;

const PIP_CERTIFICATE_STORE_OPTION: &str = "--cert";
const SHORTEST_UNAMBIGUOUS_PREFIX: &str = "--ce";

/// Return a policy-evaluation copy in which reviewed separate-value
/// certificate-store abbreviations are represented as attached options.
///
/// This prevents the certificate path from masquerading as a package operand
/// without changing the caller-submitted argv retained for audit hashing. Only
/// direct `pip`/`pip3 install` grammar and the already-verified `--ce`/`--cer`
/// abbreviation language are normalized; malformed or unknown grammar remains
/// untouched and therefore fail closed.
pub(crate) fn normalize_reviewed_pypi_certificate_store_values(
    intent: &InstallIntent,
) -> Option<InstallIntent> {
    let executable = intent.argv.first()?.as_str();
    let arguments = &intent.argv[1..];
    if !matches!(executable, "pip" | "pip3")
        || !arguments
            .first()
            .is_some_and(|argument| argument == "install")
    {
        return None;
    }

    let mut normalized = intent.clone();
    let mut changed = false;
    let mut argv = Vec::with_capacity(intent.argv.len());
    argv.extend(intent.argv.iter().take(2).cloned());

    let mut index = 2;
    while index < intent.argv.len() {
        let argument = intent.argv[index].as_str();
        if matches_pip_certificate_store_abbreviation(argument) && !argument.contains('=') {
            let value = intent.argv.get(index + 1)?;
            if value.is_empty() || value.starts_with('-') {
                return None;
            }
            argv.push(format!("{argument}={value}"));
            changed = true;
            index += 2;
            continue;
        }

        argv.push(intent.argv[index].clone());
        index += 1;
    }

    if !changed {
        return None;
    }
    normalized.argv = argv;
    Some(normalized)
}

/// Return whether a direct pip install selects a caller-controlled certificate
/// store through an accepted long-option abbreviation not covered by the
/// generic exact-option guard.
pub(crate) fn requests_unapproved_pypi_certificate_store_abbreviation(
    intent: &InstallIntent,
) -> bool {
    let Some(executable) = intent.argv.first().map(String::as_str) else {
        return false;
    };
    let arguments = &intent.argv[1..];

    matches!(executable, "pip" | "pip3")
        && arguments
            .first()
            .is_some_and(|argument| argument == "install")
        && arguments
            .iter()
            .any(|argument| matches_pip_certificate_store_abbreviation(argument))
}

/// pip's optparse-compatible parser accepts `--ce` and `--cer` for `--cert`.
/// `--c` remains ambiguous on the reviewed option surface, while the full
/// `--cert` spelling stays owned by the generic exact-option trust guard.
pub(crate) fn matches_pip_certificate_store_abbreviation(argument: &str) -> bool {
    let option = argument
        .split_once('=')
        .map_or(argument, |(option, _)| option);

    option.len() >= SHORTEST_UNAMBIGUOUS_PREFIX.len()
        && option != PIP_CERTIFICATE_STORE_OPTION
        && PIP_CERTIFICATE_STORE_OPTION.starts_with(option)
}

#[cfg(test)]
mod tests {
    use super::matches_pip_certificate_store_abbreviation;

    #[test]
    fn pip_certificate_store_abbreviations_are_bounded_to_verified_language() {
        for argument in [
            "--ce",
            "--cer",
            "--ce=/tmp/alternate.pem",
            "--cer=/tmp/alternate.pem",
        ] {
            assert!(
                matches_pip_certificate_store_abbreviation(argument),
                "accepted pip certificate-store abbreviation must be classified: {argument}"
            );
        }

        for argument in [
            "--c",
            "--cert",
            "--certificate",
            "--client-cert",
            "--cache-dir",
        ] {
            assert!(
                !matches_pip_certificate_store_abbreviation(argument),
                "ambiguous, full, or unrelated option must not be classified as a certificate-store abbreviation: {argument}"
            );
        }
    }
}
