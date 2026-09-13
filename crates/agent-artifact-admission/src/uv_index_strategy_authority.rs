use crate::InstallIntent;

const UV_INDEX_STRATEGY: &str = "--index-strategy";
const FIRST_INDEX: &str = "first-index";
const UNSAFE_FIRST_MATCH: &str = "unsafe-first-match";
const UNSAFE_BEST_MATCH: &str = "unsafe-best-match";

/// Return whether a supported `uv pip install` asks uv to search across index
/// trust boundaries instead of retaining uv's dependency-confusion-safe
/// `first-index` selection rule.
pub(crate) fn requests_unsafe_uv_index_strategy(intent: &InstallIntent) -> bool {
    let Some(arguments) = supported_uv_pip_install_arguments(intent) else {
        return false;
    };

    for (index, argument) in arguments.iter().enumerate() {
        if argument == "--" {
            break;
        }
        if let Some(value) = argument.strip_prefix("--index-strategy=") {
            if is_unsafe_strategy(value) {
                return true;
            }
            continue;
        }
        if argument == UV_INDEX_STRATEGY
            && arguments
                .get(index + 1)
                .is_some_and(|value| is_unsafe_strategy(value))
        {
            return true;
        }
    }
    false
}

/// Normalize only documented separate-value `uv pip install --index-strategy`
/// grammar so the strategy token is not mistaken for a package operand. The
/// selector itself remains in argv for ordinary command-policy validation.
pub(crate) fn normalize_reviewed_uv_index_strategy_value(
    intent: &InstallIntent,
) -> Option<InstallIntent> {
    let arguments = supported_uv_pip_install_arguments(intent)?;
    let mut value_indexes = Vec::new();

    for (index, argument) in arguments.iter().enumerate() {
        if argument == "--" {
            break;
        }
        if argument != UV_INDEX_STRATEGY {
            continue;
        }
        let Some(value) = arguments.get(index + 1) else {
            continue;
        };
        if is_documented_strategy(value) {
            // `arguments` starts at argv[3], so its following value maps to
            // argv[index + 4].
            value_indexes.push(index + 4);
        }
    }

    if value_indexes.is_empty() {
        return None;
    }

    let mut normalized = intent.clone();
    for index in value_indexes.into_iter().rev() {
        normalized.argv.remove(index);
    }
    Some(normalized)
}

fn supported_uv_pip_install_arguments(intent: &InstallIntent) -> Option<&[String]> {
    if intent.argv.first().map(String::as_str) != Some("uv")
        || intent.argv.get(1).map(String::as_str) != Some("pip")
        || intent.argv.get(2).map(String::as_str) != Some("install")
    {
        return None;
    }
    Some(&intent.argv[3..])
}

fn is_documented_strategy(value: &str) -> bool {
    matches!(value, FIRST_INDEX | UNSAFE_FIRST_MATCH | UNSAFE_BEST_MATCH)
}

fn is_unsafe_strategy(value: &str) -> bool {
    matches!(value, UNSAFE_FIRST_MATCH | UNSAFE_BEST_MATCH)
}

#[cfg(test)]
mod tests {
    use super::{
        normalize_reviewed_uv_index_strategy_value, requests_unsafe_uv_index_strategy,
    };
    use crate::InstallIntent;

    fn intent(arguments: &[&str]) -> InstallIntent {
        let mut intent = InstallIntent::unowned_llms_package_for_test();
        intent.argv = arguments.iter().map(|value| (*value).to_string()).collect();
        intent
    }

    #[test]
    fn matcher_is_exact_and_bounded_to_supported_uv_pip_install() {
        for argv in [
            vec!["uv", "pip", "install", "pkg", "--index-strategy=unsafe-best-match"],
            vec!["uv", "pip", "install", "pkg", "--index-strategy", "unsafe-first-match"],
        ] {
            assert!(requests_unsafe_uv_index_strategy(&intent(&argv)));
        }

        for argv in [
            vec!["uv", "pip", "install", "pkg", "--index-strategy=first-index"],
            vec!["uv", "pip", "install", "pkg", "--index-strateg=unsafe-best-match"],
            vec!["uv", "run", "python", "--index-strategy=unsafe-best-match"],
            vec!["uv", "pip", "install", "pkg", "--", "--index-strategy=unsafe-best-match"],
        ] {
            assert!(!requests_unsafe_uv_index_strategy(&intent(&argv)));
        }
    }

    #[test]
    fn normalizer_consumes_only_documented_separate_strategy_values() {
        let separate = intent(&[
            "uv",
            "pip",
            "install",
            "pkg",
            "--index-strategy",
            "first-index",
        ]);
        let normalized = normalize_reviewed_uv_index_strategy_value(&separate)
            .expect("documented separate strategy value must normalize");
        assert_eq!(
            normalized.argv,
            vec!["uv", "pip", "install", "pkg", "--index-strategy"]
        );

        for argv in [
            vec!["uv", "pip", "install", "pkg", "--index-strategy", "future-mode"],
            vec!["uv", "pip", "install", "pkg", "--", "--index-strategy", "first-index"],
        ] {
            assert!(normalize_reviewed_uv_index_strategy_value(&intent(&argv)).is_none());
        }
    }
}
