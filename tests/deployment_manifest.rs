//! Regression contracts for the production Kubernetes deployment manifest.

use std::borrow::Cow;

const MANIFEST: &str = include_str!("../deploy/kubernetes/waf-ids-ai-soc.yaml");
const PRODUCTION_GUIDE: &str = include_str!("../docs/deployment/production.md");

/// Secret coordinates the gateway Deployment must consume for `ADMIN_TOKEN`.
#[derive(Debug, PartialEq, Eq)]
struct ExternalAdminSecretRef<'a> {
    namespace: &'a str,
    secret_name: &'a str,
    secret_key: &'a str,
}

/// Count leading ASCII spaces so YAML indent is compared structurally.
fn leading_spaces(line: &str) -> usize {
    line.len() - line.trim_start_matches(' ').len()
}

/// Parse a single-line YAML scalar, ignoring trailing comments and normalizing
/// matching quote wrappers.
fn normalized_yaml_scalar(value: &str) -> Cow<'_, str> {
    let trimmed = value.trim();
    let mut in_single = false;
    let mut in_double = false;
    let mut previous = None;
    let mut end = trimmed.len();
    for (index, ch) in trimmed.char_indices() {
        match ch {
            '\'' if !in_double => in_single = !in_single,
            '"' if !in_single && previous != Some('\\') => in_double = !in_double,
            '#' if !in_single && !in_double && previous.is_none_or(char::is_whitespace) => {
                end = index;
                break;
            }
            _ => {}
        }
        previous = Some(ch);
    }
    let scalar = trimmed[..end].trim_end();
    if scalar.len() >= 2 {
        let bytes = scalar.as_bytes();
        let first = bytes[0];
        let last = bytes[scalar.len() - 1];
        if first == b'"' && last == b'"' {
            return decode_double_quoted_yaml_scalar(&scalar[1..scalar.len() - 1]);
        }
        if first == b'\'' && last == b'\'' {
            return Cow::Owned(scalar[1..scalar.len() - 1].replace("''", "'"));
        }
    }
    Cow::Borrowed(scalar)
}

/// Decode the YAML escape sequences relevant to duplicate env-name detection.
fn decode_double_quoted_yaml_scalar(value: &str) -> Cow<'_, str> {
    if !value.contains('\\') {
        return Cow::Borrowed(value);
    }

    let mut decoded = String::with_capacity(value.len());
    let mut chars = value.chars();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            decoded.push(ch);
            continue;
        }

        let Some(escape) = chars.next() else {
            decoded.push('\\');
            break;
        };
        match escape {
            '0' => decoded.push('\0'),
            'a' => decoded.push('\u{0007}'),
            'b' => decoded.push('\u{0008}'),
            't' | '\t' => decoded.push('\t'),
            'n' => decoded.push('\n'),
            'v' => decoded.push('\u{000B}'),
            'f' => decoded.push('\u{000C}'),
            'r' => decoded.push('\r'),
            'e' => decoded.push('\u{001B}'),
            ' ' => decoded.push(' '),
            '"' => decoded.push('"'),
            '/' => decoded.push('/'),
            '\\' => decoded.push('\\'),
            'N' => decoded.push('\u{0085}'),
            '_' => decoded.push('\u{00A0}'),
            'L' => decoded.push('\u{2028}'),
            'P' => decoded.push('\u{2029}'),
            'x' => push_escaped_codepoint(&mut decoded, &mut chars, 2, "\\x"),
            'u' => push_escaped_codepoint(&mut decoded, &mut chars, 4, "\\u"),
            'U' => push_escaped_codepoint(&mut decoded, &mut chars, 8, "\\U"),
            other => {
                decoded.push('\\');
                decoded.push(other);
            }
        }
    }

    Cow::Owned(decoded)
}

fn push_escaped_codepoint(
    decoded: &mut String,
    chars: &mut std::str::Chars<'_>,
    digits: usize,
    marker: &str,
) {
    let mut hex = String::with_capacity(digits);
    for _ in 0..digits {
        let Some(ch) = chars.next() else {
            decoded.push_str(marker);
            decoded.push_str(&hex);
            return;
        };
        if !ch.is_ascii_hexdigit() {
            decoded.push_str(marker);
            decoded.push_str(&hex);
            decoded.push(ch);
            return;
        }
        hex.push(ch);
    }

    if let Ok(value) = u32::from_str_radix(&hex, 16) {
        if let Some(codepoint) = char::from_u32(value) {
            decoded.push(codepoint);
            return;
        }
    }

    decoded.push_str(marker);
    decoded.push_str(&hex);
}

/// Whether a `- name:` YAML line names the expected entry, with quote tolerance.
fn yaml_named_entry_matches(line: &str, item_indent: usize, expected_name: &str) -> bool {
    if leading_spaces(line) != item_indent {
        return false;
    }
    let Some(raw_name) = line.trim().strip_prefix("- name:") else {
        return false;
    };
    normalized_yaml_scalar(raw_name) == expected_name
}

/// Read `child_key` from the mapping that starts at `parent_key`/`parent_indent`.
fn mapping_value<'a>(
    lines: &[&'a str],
    parent_key: &str,
    parent_indent: usize,
    child_key: &str,
) -> Option<&'a str> {
    let parent_index = lines
        .iter()
        .position(|line| leading_spaces(line) == parent_indent && line.trim() == parent_key)?;

    lines[parent_index + 1..]
        .iter()
        .take_while(|line| line.trim().is_empty() || leading_spaces(line) > parent_indent)
        .find_map(|line| {
            line.trim()
                .strip_prefix(child_key)
                .map(str::trim)
                .filter(|value| !value.is_empty())
        })
}

/// Lines that belong to the YAML block nested under `parent_key`.
fn nested_block<'a>(lines: &[&'a str], parent_key: &str, parent_indent: usize) -> Vec<&'a str> {
    let Some(parent_index) = lines
        .iter()
        .position(|line| leading_spaces(line) == parent_indent && line.trim() == parent_key)
    else {
        return Vec::new();
    };

    lines[parent_index + 1..]
        .iter()
        .take_while(|line| line.trim().is_empty() || leading_spaces(line) > parent_indent)
        .copied()
        .collect()
}

/// Slice of a YAML list item whose `- name:` equals `item_name`.
fn named_list_item_block<'a>(
    lines: &[&'a str],
    item_name: &str,
    item_indent: usize,
) -> Vec<&'a str> {
    let expected = format!("- name: {item_name}");
    let Some(item_index) = lines
        .iter()
        .position(|line| leading_spaces(line) == item_indent && line.trim() == expected)
    else {
        return Vec::new();
    };

    lines[item_index..]
        .iter()
        .enumerate()
        .take_while(|(offset, line)| {
            *offset == 0 || line.trim().is_empty() || leading_spaces(line) > item_indent
        })
        .map(|(_, line)| *line)
        .collect()
}

/// Locate `ADMIN_TOKEN` on the `waf-ids-ai-soc` gateway container only.
///
/// Duplicate entries, literal fallback values, and `secretKeyRef.optional: true`
/// are treated as absent (fail closed).
fn external_admin_secret_ref(manifest: &str) -> Option<ExternalAdminSecretRef<'_>> {
    manifest.split("\n---\n").find_map(|document| {
        let lines = document.lines().collect::<Vec<_>>();
        if !lines.iter().any(|line| line.trim() == "kind: Deployment") {
            return None;
        }

        if mapping_value(&lines, "metadata:", 0, "name:") != Some("waf-ids-ai-soc") {
            return None;
        }

        let namespace = mapping_value(&lines, "metadata:", 0, "namespace:")?;
        let workload_spec = nested_block(&lines, "spec:", 0);
        let pod_template = nested_block(&workload_spec, "template:", 2);
        let pod_spec = nested_block(&pod_template, "spec:", 4);
        let containers = nested_block(&pod_spec, "containers:", 6);
        let gateway = named_list_item_block(&containers, "gateway", 8);
        let env = nested_block(&gateway, "env:", 10);
        let admin_token_entries = env
            .iter()
            .filter(|line| yaml_named_entry_matches(line, 12, "ADMIN_TOKEN"))
            .count();
        if admin_token_entries != 1 {
            return None;
        }

        let env_block = named_list_item_block(&env, "ADMIN_TOKEN", 12);
        if env_block
            .iter()
            .any(|line| line.trim().starts_with("value:"))
        {
            return None;
        }
        let secret_ref_index = env_block
            .iter()
            .position(|line| line.trim() == "secretKeyRef:")?;
        let secret_ref_indent = leading_spaces(env_block[secret_ref_index]);
        let secret_ref_block = env_block[secret_ref_index + 1..]
            .iter()
            .take_while(|line| line.trim().is_empty() || leading_spaces(line) > secret_ref_indent)
            .copied()
            .collect::<Vec<_>>();

        let secret_name = secret_ref_block.iter().find_map(|line| {
            line.trim()
                .strip_prefix("name:")
                .map(str::trim)
                .filter(|value| !value.is_empty())
        })?;
        let secret_key = secret_ref_block.iter().find_map(|line| {
            line.trim()
                .strip_prefix("key:")
                .map(str::trim)
                .filter(|value| !value.is_empty())
        })?;
        match secret_ref_block.iter().find_map(|line| {
            line.trim()
                .strip_prefix("optional:")
                .map(str::trim)
                .filter(|value| !value.is_empty())
        }) {
            None | Some("false") => {}
            Some(_) => return None,
        }

        Some(ExternalAdminSecretRef {
            namespace,
            secret_name,
            secret_key,
        })
    })
}

#[test]
fn shipped_manifest_contains_no_admin_secret_object() {
    assert!(
        !MANIFEST.lines().any(|line| line.trim() == "kind: Secret"),
        "the distributable manifest must not create an administrator Secret"
    );
    assert!(
        !MANIFEST.contains("replace-with-secret-manager-sync"),
        "the distributable manifest must not contain a reusable administrator credential"
    );
}

#[test]
fn deployment_requires_the_external_admin_secret_contract() {
    assert_eq!(
        external_admin_secret_ref(MANIFEST),
        Some(ExternalAdminSecretRef {
            namespace: "waf-ids-ai-soc",
            secret_name: "waf-ids-ai-soc-admin",
            secret_key: "ADMIN_TOKEN",
        })
    );
}

#[test]
fn decoy_secret_text_cannot_satisfy_the_structural_contract() {
    let decoy_manifest = r#"apiVersion: apps/v1
kind: Deployment
metadata:
  name: waf-ids-ai-soc
  namespace: another-namespace
spec:
  template:
    spec:
      containers:
        - name: gateway
          env:
            - name: ADMIN_TOKEN
              valueFrom:
                secretKeyRef:
                  name: another-secret
                  key: ANOTHER_KEY
# name: waf-ids-ai-soc-admin
# key: ADMIN_TOKEN
"#;

    assert_ne!(
        external_admin_secret_ref(decoy_manifest),
        Some(ExternalAdminSecretRef {
            namespace: "waf-ids-ai-soc",
            secret_name: "waf-ids-ai-soc-admin",
            secret_key: "ADMIN_TOKEN",
        })
    );
}

#[test]
fn another_deployment_cannot_satisfy_the_target_secret_contract() {
    let reverse_order_manifest = r#"apiVersion: apps/v1
kind: Deployment
metadata:
  name: unrelated-worker
  namespace: waf-ids-ai-soc
spec:
  template:
    spec:
      containers:
        - name: worker
          env:
            - name: ADMIN_TOKEN
              valueFrom:
                secretKeyRef:
                  name: waf-ids-ai-soc-admin
                  key: ADMIN_TOKEN
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: waf-ids-ai-soc
  namespace: waf-ids-ai-soc
spec:
  template:
    spec:
      containers:
        - name: gateway
          env:
            - name: ADMIN_TOKEN
              valueFrom:
                secretKeyRef:
                  name: wrong-secret
                  key: WRONG_KEY
"#;

    assert_eq!(
        external_admin_secret_ref(reverse_order_manifest),
        Some(ExternalAdminSecretRef {
            namespace: "waf-ids-ai-soc",
            secret_name: "wrong-secret",
            secret_key: "WRONG_KEY",
        })
    );
}

#[test]
fn init_container_cannot_satisfy_the_gateway_secret_contract() {
    let init_container_decoy = r#"apiVersion: apps/v1
kind: Deployment
metadata:
  name: waf-ids-ai-soc
  namespace: waf-ids-ai-soc
spec:
  template:
    spec:
      initContainers:
        - name: decoy
          env:
            - name: ADMIN_TOKEN
              valueFrom:
                secretKeyRef:
                  name: waf-ids-ai-soc-admin
                  key: ADMIN_TOKEN
      containers:
        - name: gateway
          env:
            - name: ADMIN_TOKEN
              valueFrom:
                secretKeyRef:
                  name: wrong-secret
                  key: WRONG_KEY
"#;

    assert_eq!(
        external_admin_secret_ref(init_container_decoy),
        Some(ExternalAdminSecretRef {
            namespace: "waf-ids-ai-soc",
            secret_name: "wrong-secret",
            secret_key: "WRONG_KEY",
        })
    );
}

#[test]
fn optional_admin_secret_reference_fails_closed() {
    let optional_secret = r#"apiVersion: apps/v1
kind: Deployment
metadata:
  name: waf-ids-ai-soc
  namespace: waf-ids-ai-soc
spec:
  template:
    spec:
      containers:
        - name: gateway
          env:
            - name: ADMIN_TOKEN
              valueFrom:
                secretKeyRef:
                  name: waf-ids-ai-soc-admin
                  key: ADMIN_TOKEN
                  optional: true
"#;

    assert_eq!(external_admin_secret_ref(optional_secret), None);
}

#[test]
fn explicitly_required_admin_secret_reference_is_accepted() {
    let required_secret = r#"apiVersion: apps/v1
kind: Deployment
metadata:
  name: waf-ids-ai-soc
  namespace: waf-ids-ai-soc
spec:
  template:
    spec:
      containers:
        - name: gateway
          env:
            - name: ADMIN_TOKEN
              valueFrom:
                secretKeyRef:
                  name: waf-ids-ai-soc-admin
                  key: ADMIN_TOKEN
                  optional: false
"#;

    assert_eq!(
        external_admin_secret_ref(required_secret),
        Some(ExternalAdminSecretRef {
            namespace: "waf-ids-ai-soc",
            secret_name: "waf-ids-ai-soc-admin",
            secret_key: "ADMIN_TOKEN",
        })
    );
}

#[test]
fn duplicate_admin_token_entries_fail_closed() {
    let duplicate_admin_token = r#"apiVersion: apps/v1
kind: Deployment
metadata:
  name: waf-ids-ai-soc
  namespace: waf-ids-ai-soc
spec:
  template:
    spec:
      containers:
        - name: gateway
          env:
            - name: ADMIN_TOKEN
              valueFrom:
                secretKeyRef:
                  name: waf-ids-ai-soc-admin
                  key: ADMIN_TOKEN
                  optional: false
            - name: ADMIN_TOKEN
              value: another-repository-visible-fallback
"#;

    assert_eq!(external_admin_secret_ref(duplicate_admin_token), None);
}

#[test]
fn quoted_duplicate_admin_token_entries_fail_closed() {
    let double_quoted_duplicate = r#"apiVersion: apps/v1
kind: Deployment
metadata:
  name: waf-ids-ai-soc
  namespace: waf-ids-ai-soc
spec:
  template:
    spec:
      containers:
        - name: gateway
          env:
            - name: ADMIN_TOKEN
              valueFrom:
                secretKeyRef:
                  name: waf-ids-ai-soc-admin
                  key: ADMIN_TOKEN
                  optional: false
            - name: "ADMIN_TOKEN"
              value: another-repository-visible-fallback
"#;
    let single_quoted_duplicate = r#"apiVersion: apps/v1
kind: Deployment
metadata:
  name: waf-ids-ai-soc
  namespace: waf-ids-ai-soc
spec:
  template:
    spec:
      containers:
        - name: gateway
          env:
            - name: ADMIN_TOKEN
              valueFrom:
                secretKeyRef:
                  name: waf-ids-ai-soc-admin
                  key: ADMIN_TOKEN
                  optional: false
            - name: 'ADMIN_TOKEN'
              value: another-repository-visible-fallback
"#;

    assert_eq!(external_admin_secret_ref(double_quoted_duplicate), None);
    assert_eq!(external_admin_secret_ref(single_quoted_duplicate), None);
}

#[test]
fn commented_quoted_duplicate_admin_token_entries_fail_closed() {
    let commented_duplicate = r#"apiVersion: apps/v1
kind: Deployment
metadata:
  name: waf-ids-ai-soc
  namespace: waf-ids-ai-soc
spec:
  template:
    spec:
      containers:
        - name: gateway
          env:
            - name: ADMIN_TOKEN
              valueFrom:
                secretKeyRef:
                  name: waf-ids-ai-soc-admin
                  key: ADMIN_TOKEN
                  optional: false
            - name: "ADMIN_TOKEN" # duplicated fallback entry
              value: another-repository-visible-fallback
"#;

    assert_eq!(external_admin_secret_ref(commented_duplicate), None);
}

#[test]
fn hex_escaped_duplicate_admin_token_entries_fail_closed() {
    let escaped_duplicate = r#"apiVersion: apps/v1
kind: Deployment
metadata:
  name: waf-ids-ai-soc
  namespace: waf-ids-ai-soc
spec:
  template:
    spec:
      containers:
        - name: gateway
          env:
            - name: ADMIN_TOKEN
              valueFrom:
                secretKeyRef:
                  name: waf-ids-ai-soc-admin
                  key: ADMIN_TOKEN
                  optional: false
            - name: "\x41DMIN_TOKEN"
              value: another-repository-visible-fallback
"#;

    assert_eq!(external_admin_secret_ref(escaped_duplicate), None);
}

#[test]
fn unicode_escaped_duplicate_admin_token_entries_fail_closed() {
    let escaped_duplicate = r#"apiVersion: apps/v1
kind: Deployment
metadata:
  name: waf-ids-ai-soc
  namespace: waf-ids-ai-soc
spec:
  template:
    spec:
      containers:
        - name: gateway
          env:
            - name: ADMIN_TOKEN
              valueFrom:
                secretKeyRef:
                  name: waf-ids-ai-soc-admin
                  key: ADMIN_TOKEN
                  optional: false
            - name: "\u0041DMIN_TOKEN"
              value: another-repository-visible-fallback
"#;

    assert_eq!(external_admin_secret_ref(escaped_duplicate), None);
}

#[test]
fn fresh_install_bootstraps_namespace_before_secret_provisioning() {
    let namespace_bootstrap =
        "kubectl create namespace waf-ids-ai-soc --dry-run=client -o yaml | kubectl apply -f -";
    let bootstrap_index = PRODUCTION_GUIDE
        .find(namespace_bootstrap)
        .expect("fresh-install instructions must create the namespace idempotently first");
    let secret_index = PRODUCTION_GUIDE
        .find("secret-management control plane")
        .expect("production guide must retain external secret provisioning");

    assert!(
        bootstrap_index < secret_index,
        "namespace bootstrap must precede namespaced Secret provisioning"
    );
}
