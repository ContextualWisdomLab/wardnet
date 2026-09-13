use crate::InstallIntent;
use crate::pypi_certificate_store_authority::matches_pip_certificate_store_abbreviation;
use crate::pypi_client_certificate_authority::matches_pip_client_certificate_option;
use crate::pypi_proxy_authority::{
    is_attached_direct_pip_proxy_selector, is_direct_pip_proxy_value_selector,
};
use crate::pypi_python_interpreter_authority::matches_pip_python_interpreter_option;
use crate::pypi_registry_authority::{
    is_reviewed_pip_no_index_selector, is_reviewed_pip_registry_value_selector,
};

/// Canonicalize only reviewed direct-pip General Options for policy evaluation.
///
/// pip parses General Options before command selection. Wardnet preserves the
/// submitted argv as audit evidence, while this bounded parser seam moves only
/// already-reviewed denied authority selectors behind `install` so the normal
/// command and artifact policy can evaluate their values without inventing
/// package operands. Unknown pre-command grammar remains untouched and fails
/// closed through the ordinary command path.
pub(crate) fn normalize_reviewed_direct_pip_global_options(
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
    let mut reviewed_global_arguments = Vec::new();
    while index < arguments.len() {
        let argument = arguments[index].as_str();
        if argument == "install" {
            if reviewed_global_arguments.is_empty() {
                return None;
            }

            let mut normalized = intent.clone();
            let mut argv = Vec::with_capacity(intent.argv.len());
            argv.push(executable.to_string());
            argv.push("install".to_string());
            argv.extend(reviewed_global_arguments);
            argv.extend(arguments[index + 1..].iter().cloned());
            normalized.argv = argv;
            return Some(normalized);
        }

        if is_direct_pip_proxy_value_selector(argument) {
            push_separate_value_argument(arguments, &mut reviewed_global_arguments, &mut index)?;
            continue;
        }

        if is_attached_direct_pip_proxy_selector(argument) {
            reviewed_global_arguments.push(arguments[index].clone());
            index += 1;
            continue;
        }

        if is_reviewed_pip_registry_value_selector(argument) {
            if let Some((_, value)) = argument.split_once('=') {
                if value.is_empty() {
                    return None;
                }
                reviewed_global_arguments.push(arguments[index].clone());
                index += 1;
            } else {
                push_attached_normalized_value_argument(
                    arguments,
                    &mut reviewed_global_arguments,
                    &mut index,
                )?;
            }
            continue;
        }

        if is_reviewed_pip_no_index_selector(argument) {
            reviewed_global_arguments.push(arguments[index].clone());
            index += 1;
            continue;
        }

        if matches_pip_certificate_store_abbreviation(argument) {
            if let Some((_, value)) = argument.split_once('=') {
                if value.is_empty() {
                    return None;
                }
                reviewed_global_arguments.push(arguments[index].clone());
                index += 1;
            } else {
                push_separate_value_argument(
                    arguments,
                    &mut reviewed_global_arguments,
                    &mut index,
                )?;
            }
            continue;
        }

        if matches_pip_client_certificate_option(argument) {
            if let Some((_, value)) = argument.split_once('=') {
                if value.is_empty() {
                    return None;
                }
                reviewed_global_arguments.push(arguments[index].clone());
                index += 1;
            } else {
                // The client-certificate path is consumed option grammar, not an
                // artifact operand. Attach it only in the internal policy copy;
                // admission_decision restores audit identity from submitted argv.
                push_attached_normalized_value_argument(
                    arguments,
                    &mut reviewed_global_arguments,
                    &mut index,
                )?;
            }
            continue;
        }

        if matches_pip_python_interpreter_option(argument) {
            let value = if let Some((_, value)) = argument.split_once('=') {
                if value.is_empty() {
                    return None;
                }
                index += 1;
                value.to_string()
            } else {
                let value = arguments.get(index + 1)?;
                if value == "install" || value.starts_with('-') || value.is_empty() {
                    return None;
                }
                index += 2;
                value.clone()
            };

            // A verified pre-command abbreviation is General Option grammar, but
            // the same spelling can be ambiguous in `pip install` grammar because
            // that parser also defines `--python-version`. Canonicalize only the
            // internal policy copy to exact `--python=VALUE` so the pre-command
            // meaning survives phase normalization without widening post-command
            // authority. The submitted argv remains the audit/hash authority.
            reviewed_global_arguments.push(format!("--python={value}"));
            continue;
        }

        return None;
    }

    None
}

fn push_attached_normalized_value_argument(
    arguments: &[String],
    reviewed_global_arguments: &mut Vec<String>,
    index: &mut usize,
) -> Option<()> {
    let value = arguments.get(*index + 1)?;
    if value == "install" || value.starts_with('-') || value.is_empty() {
        return None;
    }

    reviewed_global_arguments.push(format!("{}={value}", arguments[*index]));
    *index += 2;
    Some(())
}

fn push_separate_value_argument(
    arguments: &[String],
    reviewed_global_arguments: &mut Vec<String>,
    index: &mut usize,
) -> Option<()> {
    let value = arguments.get(*index + 1)?;
    if value == "install" || value.starts_with('-') || value.is_empty() {
        return None;
    }

    reviewed_global_arguments.push(arguments[*index].clone());
    reviewed_global_arguments.push(value.clone());
    *index += 2;
    Some(())
}
