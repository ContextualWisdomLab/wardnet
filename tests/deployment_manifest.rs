//! Regression contracts for the production Kubernetes deployment manifest.

const MANIFEST: &str = include_str!("../deploy/kubernetes/waf-ids-ai-soc.yaml");

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
    assert!(MANIFEST.contains("secretKeyRef:"));
    assert!(MANIFEST.contains("name: waf-ids-ai-soc-admin"));
    assert!(MANIFEST.contains("key: ADMIN_TOKEN"));
}
