use crate::InstallIntent;

/// Return a policy-evaluation view in which uv's package-scoped build-isolation
/// selector value cannot masquerade as a second requested install artifact.
/// The submitted argv is preserved separately for the final decision and audit
/// digest; this normalization does not authorize the denied override.
pub(crate) fn normalize_uv_build_isolation_package_selector(
    intent: &InstallIntent,
) -> Option<InstallIntent> {
    let arguments = &intent.argv;
    if arguments.first().map(String::as_str) != Some("uv")
        || arguments.get(1).map(String::as_str) != Some("pip")
        || arguments.get(2).map(String::as_str) != Some("install")
    {
        return None;
    }

    let mut changed = false;
    let mut normalized = intent.clone();
    normalized.argv = arguments
        .iter()
        .enumerate()
        .filter_map(|(index, argument)| {
            let is_consumed_selector_value = index > 3
                && arguments
                    .get(index - 1)
                    .is_some_and(|previous| previous == "--no-build-isolation-package")
                && !argument.starts_with('-');
            if is_consumed_selector_value {
                changed = true;
                None
            } else {
                Some(argument.clone())
            }
        })
        .collect();

    changed.then_some(normalized)
}

/// Return whether a supported `uv pip install` invocation asks to disable the
/// reviewed PEP 517 build-isolation boundary.
pub(crate) fn requests_unapproved_uv_build_isolation_override(intent: &InstallIntent) -> bool {
    let Some(executable) = intent.argv.first().map(String::as_str) else {
        return false;
    };
    let arguments = &intent.argv[1..];

    executable == "uv"
        && arguments.first().is_some_and(|argument| argument == "pip")
        && arguments
            .get(1)
            .is_some_and(|argument| argument == "install")
        && arguments.iter().skip(2).any(|argument| {
            argument == "--no-build-isolation"
                || argument == "--no-build-isolation-package"
                || argument.starts_with("--no-build-isolation-package=")
        })
}

#[cfg(test)]
mod tests {
    use super::{
        normalize_uv_build_isolation_package_selector,
        requests_unapproved_uv_build_isolation_override,
    };
    use crate::InstallIntent;

    #[test]
    fn exact_package_selector_value_is_removed_from_policy_evaluation_view() {
        let mut intent = InstallIntent::unowned_llms_package_for_test();
        intent.argv = vec![
            "uv".to_string(),
            "pip".to_string(),
            "install".to_string(),
            "cwl-example==1.2.3".to_string(),
            "--no-build-isolation-package".to_string(),
            "cwl-example".to_string(),
        ];

        let normalized = normalize_uv_build_isolation_package_selector(&intent)
            .expect("exact selector must produce a policy-evaluation view");

        assert_eq!(
            normalized.argv,
            vec![
                "uv",
                "pip",
                "install",
                "cwl-example==1.2.3",
                "--no-build-isolation-package",
            ]
        );
        assert!(requests_unapproved_uv_build_isolation_override(&intent));
    }

    #[test]
    fn uv_long_option_lookalike_is_not_classified_as_build_isolation_authority() {
        let mut intent = InstallIntent::unowned_llms_package_for_test();
        intent.argv = vec![
            "uv".to_string(),
            "pip".to_string(),
            "install".to_string(),
            "cwl-example==1.2.3".to_string(),
            "--no-build-isolatio".to_string(),
        ];

        assert!(normalize_uv_build_isolation_package_selector(&intent).is_none());
        assert!(!requests_unapproved_uv_build_isolation_override(&intent));
    }
}
