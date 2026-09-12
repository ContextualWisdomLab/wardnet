use crate::InstallIntent;

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

/// Return whether `arguments[index]` is the separate-token package value
/// consumed by uv's package-scoped build-isolation override. The override
/// remains denied; this helper only keeps its selector value from being
/// misclassified as a second requested install artifact.
pub(crate) fn is_uv_build_isolation_package_selector_value(
    executable: &str,
    arguments: &[String],
    index: usize,
) -> bool {
    if executable != "uv"
        || !arguments.first().is_some_and(|argument| argument == "pip")
        || !arguments
            .get(1)
            .is_some_and(|argument| argument == "install")
    {
        return false;
    }

    index
        .checked_sub(1)
        .and_then(|previous| arguments.get(previous))
        .is_some_and(|argument| argument == "--no-build-isolation-package")
}

#[cfg(test)]
mod tests {
    use super::is_uv_build_isolation_package_selector_value;

    #[test]
    fn separate_package_selector_value_is_consumed_only_for_exact_uv_option() {
        let arguments = vec![
            "pip".to_string(),
            "install".to_string(),
            "--no-build-isolation-package".to_string(),
            "cwl-example".to_string(),
        ];

        assert!(is_uv_build_isolation_package_selector_value(
            "uv", &arguments, 3
        ));
        assert!(!is_uv_build_isolation_package_selector_value(
            "pip", &arguments, 3
        ));

        let lookalike = vec![
            "pip".to_string(),
            "install".to_string(),
            "--no-build-isolation-packag".to_string(),
            "cwl-example".to_string(),
        ];
        assert!(!is_uv_build_isolation_package_selector_value(
            "uv", &lookalike, 3
        ));
    }
}
