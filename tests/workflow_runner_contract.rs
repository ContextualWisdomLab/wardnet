//! Repository contract for isolated self-hosted runner selection.
//!
//! Runner labels are routing requirements, not proof of isolation or capacity.
//! General CI executes repository code and must not select privileged control,
//! scanner or inference-host pools. Provisioning and actual job receipts remain
//! separate acceptance obligations.

use std::fs;
use std::path::Path;

const ISOLATED_RUNNER: &str = "[self-hosted, Linux, X64, cwlab-ci-isolated]";
const RUNNER_BACKED_WORKFLOWS: &[&str] = &[
    ".github/workflows/ci.yml",
    ".github/workflows/fuzz.yml",
    ".github/workflows/scorecard-analysis.yml",
];

#[test]
fn every_local_workflow_requires_the_isolated_self_hosted_pool() {
    let repository = Path::new(env!("CARGO_MANIFEST_DIR"));
    let directory = repository.join(".github/workflows");
    let mut observed = Vec::new();
    for file in fs::read_dir(directory).unwrap() {
        let path = file.unwrap().path();
        if !matches!(
            path.extension().and_then(|ext| ext.to_str()),
            Some("yml" | "yaml")
        ) {
            continue;
        }
        let workflow = fs::read_to_string(&path).unwrap();
        let runners: Vec<_> = workflow
            .lines()
            .filter_map(|line| line.trim().strip_prefix("runs-on:"))
            .map(str::trim)
            .collect();
        assert!(
            !runners.is_empty(),
            "{} must have a concrete runner",
            path.display()
        );
        assert!(
            runners.iter().all(|runner| *runner == ISOLATED_RUNNER),
            "{} must select only {ISOLATED_RUNNER}; found {runners:?}",
            path.display()
        );
        observed.push(
            path.strip_prefix(repository)
                .unwrap()
                .to_str()
                .unwrap()
                .to_string(),
        );
    }
    observed.sort();
    assert_eq!(
        observed,
        RUNNER_BACKED_WORKFLOWS
            .iter()
            .map(|path| path.to_string())
            .collect::<Vec<_>>()
    );
}

// A deliberately limited block-mapping reader for these repository workflows.
// Unsupported checkout options fail closed; this is not a general YAML parser.
fn checkout_credentials_are_disabled(workflow: &str) -> bool {
    fn scalar(value: &str) -> Option<&str> {
        let mut quote = None;
        let mut end = value.len();
        for (index, character) in value.char_indices() {
            match (quote, character) {
                (None, '\'' | '"') => quote = Some(character),
                (Some(delimiter), closing) if delimiter == closing => quote = None,
                (None, '#') if index == 0 || value[..index].ends_with(char::is_whitespace) => {
                    end = index;
                    break;
                }
                _ => {}
            }
        }
        if quote.is_some() {
            return None;
        }
        let value = value[..end].trim();
        if value.starts_with(['\'', '"']) {
            let delimiter = value.chars().next()?;
            value.strip_prefix(delimiter)?.strip_suffix(delimiter)
        } else {
            Some(value)
        }
    }

    fn checkout_step(lines: &[&str], sequence_indent: usize) -> Option<bool> {
        let field_indent = sequence_indent + 2;
        let mut uses = Vec::new();
        let mut options = Vec::new();
        for (index, line) in lines.iter().enumerate() {
            let indent = line.len() - line.trim_start().len();
            let content = if index == 0 {
                line.trim_start().strip_prefix("- ")?
            } else {
                if indent != field_indent {
                    continue;
                }
                line.trim_start()
            };
            if let Some(value) = content.strip_prefix("uses:") {
                uses.push(scalar(value)?);
            }
            if let Some(value) = content.strip_prefix("with:") {
                options.push((index, scalar(value)?));
            }
        }
        if !uses
            .iter()
            .any(|action| action.starts_with("actions/checkout@"))
        {
            return Some(false);
        }
        if uses.len() != 1 || options.len() != 1 || !options[0].1.is_empty() {
            return None;
        }
        let mut credentials = Vec::new();
        for line in &lines[options[0].0 + 1..] {
            if line.trim().is_empty() || line.trim_start().starts_with('#') {
                continue;
            }
            let indent = line.len() - line.trim_start().len();
            if indent <= field_indent {
                break;
            }
            if indent == field_indent + 2
                && let Some(value) = line.trim_start().strip_prefix("persist-credentials:")
            {
                // Require the literal YAML boolean, not a quoted string/expression.
                if value.trim_start().starts_with(['\'', '"']) {
                    return None;
                }
                credentials.push(scalar(value)?);
            }
        }
        (credentials == ["false"]).then_some(true)
    }

    if workflow.lines().any(|line| line.starts_with('\t')) {
        return false;
    }
    let lines: Vec<_> = workflow.lines().collect();
    let mut checkouts = 0;
    let mut index = 0;
    while index < lines.len() {
        let line = lines[index];
        let indent = line.len() - line.trim_start().len();
        let Some(value) = line.trim_start().strip_prefix("steps:") else {
            index += 1;
            continue;
        };
        if indent != 4 || scalar(value) != Some("") {
            return false;
        }
        let steps_indent = indent;
        index += 1;
        while index < lines.len() {
            let line = lines[index];
            if line.trim().is_empty() || line.trim_start().starts_with('#') {
                index += 1;
                continue;
            }
            let indent = line.len() - line.trim_start().len();
            if indent <= steps_indent {
                break;
            }
            if indent != steps_indent + 2 || !line.trim_start().starts_with("- ") {
                return false;
            }
            let start = index;
            index += 1;
            while index < lines.len() {
                let next = lines[index];
                if !next.trim().is_empty()
                    && !next.trim_start().starts_with('#')
                    && next.len() - next.trim_start().len() <= indent
                {
                    break;
                }
                index += 1;
            }
            match checkout_step(&lines[start..index], indent) {
                Some(true) => checkouts += 1,
                Some(false) => {}
                None => return false,
            }
        }
    }
    checkouts > 0
}

#[test]
fn checkout_credentials_are_not_persisted_on_self_hosted_workers() {
    let repository = Path::new(env!("CARGO_MANIFEST_DIR"));
    for relative in RUNNER_BACKED_WORKFLOWS {
        let workflow = fs::read_to_string(repository.join(relative)).unwrap();
        assert!(
            checkout_credentials_are_disabled(&workflow),
            "{relative} must not leave checkout credentials in the workspace"
        );
    }
}

#[test]
fn commented_credential_option_cannot_authorize_checkout() {
    let safe = "jobs:\n  rust:\n    steps:\n      - uses: actions/checkout@fixture\n        with:\n          persist-credentials: false\n";
    let unsafe_workflow =
        safe.replace("persist-credentials: false", "# persist-credentials: false");
    assert!(checkout_credentials_are_disabled(safe));
    assert!(
        !checkout_credentials_are_disabled(&unsafe_workflow),
        "a comment must not authorize credential persistence"
    );
}

fn checkout_fixture(action: &str, option: &str) -> String {
    format!(
        "jobs:\n  rust:\n    steps:\n      - uses: {action}\n        with:\n          persist-credentials: {option}\n"
    )
}

#[test]
fn every_checkout_step_requires_its_own_literal_false() {
    for action in [
        "actions/checkout@fixture",
        "'actions/checkout@fixture'",
        "\"actions/checkout@fixture\"",
    ] {
        let safe = checkout_fixture(action, "false");
        assert!(checkout_credentials_are_disabled(&safe));
        for option in ["true", "'false'", "\"false\"", "${{ false }}", ""] {
            let unsafe_step = format!(
                "      - uses:  {action}\n        with:\n          persist-credentials: {option}\n"
            );
            assert!(
                !checkout_credentials_are_disabled(&(safe.clone() + &unsafe_step)),
                "unsafe later checkout option {option:?} must be rejected"
            );
        }
        let second_safe = format!(
            "      - uses:\t{action}\n        with:\n          persist-credentials: false # literal control\n"
        );
        assert!(checkout_credentials_are_disabled(&(safe + &second_safe)));
    }
}

#[test]
fn unrelated_step_or_job_option_cannot_authorize_checkout() {
    let unsafe_workflow = "jobs:\n  rust:\n    steps:\n      - uses: actions/checkout@fixture\n      - name: unrelated\n        with:\n          persist-credentials: false\n";
    assert!(!checkout_credentials_are_disabled(unsafe_workflow));
    let other_job = "  other:\n    steps:\n      - name: not checkout\n        with:\n          persist-credentials: false\n";
    let missing_option = "jobs:\n  rust:\n    steps:\n      - uses: actions/checkout@fixture\n";
    assert!(!checkout_credentials_are_disabled(
        &(missing_option.to_owned() + other_job)
    ));
    let no_checkout = "jobs:\n  rust:\n    steps:\n      - run: |\n          echo actions/checkout@fixture\n          echo persist-credentials: false\n";
    assert!(!checkout_credentials_are_disabled(no_checkout));
}

#[test]
fn commented_steps_header_cannot_hide_an_unsafe_later_job() {
    let safe = checkout_fixture("actions/checkout@fixture", "false");
    let unsafe_job = "  later:\n    steps: # ordinary inline comment\n      - uses: actions/checkout@fixture\n        with:\n          persist-credentials: true\n";
    assert!(checkout_credentials_are_disabled(&safe));
    assert!(
        !checkout_credentials_are_disabled(&(safe.clone() + unsafe_job)),
        "a commented steps header must not hide a later unsafe checkout"
    );
    let safe_job = unsafe_job.replace("persist-credentials: true", "persist-credentials: false");
    assert!(checkout_credentials_are_disabled(&(safe + &safe_job)));
}

#[test]
fn ambiguous_or_nonliteral_checkout_configuration_fails_closed() {
    let safe = checkout_fixture("actions/checkout@fixture", "false");
    for option in ["false#not-a-comment", "false extra", "False", "null"] {
        assert!(
            !checkout_credentials_are_disabled(&checkout_fixture(
                "actions/checkout@fixture",
                option
            )),
            "unsupported credential scalar {option:?} must not pass"
        );
    }
    let duplicate = safe.replace(
        "persist-credentials: false",
        "persist-credentials: false\n          persist-credentials: true",
    );
    assert!(!checkout_credentials_are_disabled(&duplicate));
    let inline = safe.replace(
        "with:\n          persist-credentials: false",
        "with: { persist-credentials: false }",
    );
    assert!(!checkout_credentials_are_disabled(&inline));
    let wrong_depth = safe.replace(
        "          persist-credentials",
        "        persist-credentials",
    );
    assert!(!checkout_credentials_are_disabled(&wrong_depth));
}
