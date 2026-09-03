use std::fs;

#[test]
fn target_deployment_validation_must_not_stop_at_the_first_match() {
    let source = fs::read_to_string("tests/deployment_manifest.rs")
        .expect("deployment manifest contract source must remain available");

    assert!(
        !source.contains("manifest.split(\"\\n---\\n\").find_map(|document|"),
        "first-match parsing can hide a later Deployment with the same resource identity"
    );
}
