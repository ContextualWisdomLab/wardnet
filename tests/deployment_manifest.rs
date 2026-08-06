//! Regression contracts for the production Kubernetes deployment manifest.

const MANIFEST: &str = include_str!("../deploy/kubernetes/waf-ids-ai-soc.yaml");

#[derive(Debug, PartialEq, Eq)]
struct ExternalAdminSecretRef<'a> {
    namespace: &'a str,
    secret_name: &'a str,
    secret_key: &'a str,
}

fn leading_spaces(line: &str) -> usize {
    line.len() - line.trim_start_matches(' ').len()
}

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

fn external_admin_secret_ref(manifest: &str) -> Option<ExternalAdminSecretRef<'_>> {
    manifest.split("\n---\n").find_map(|document| {
        let lines = document.lines().collect::<Vec<_>>();
        if !lines.iter().any(|line| line.trim() == "kind: Deployment") {
            return None;
        }

        let namespace = mapping_value(&lines, "metadata:", 0, "namespace:")?;
        let env_index = lines
            .iter()
            .position(|line| line.trim() == "- name: ADMIN_TOKEN")?;
        let env_indent = leading_spaces(lines[env_index]);
        let env_block = lines[env_index + 1..]
            .iter()
            .take_while(|line| line.trim().is_empty() || leading_spaces(line) > env_indent)
            .copied()
            .collect::<Vec<_>>();
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
