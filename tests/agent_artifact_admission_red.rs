//! RED contract for issue #128.
//!
//! This test intentionally lands before the new crate. The first PR head must
//! fail because Wardnet has no agent artifact admission boundary yet. The next
//! implementation commit moves this regression into the owning crate.

use wardnet_agent_artifact_admission::{AdmissionPolicy, InstallIntent, admission_decision};

#[test]
fn unowned_package_from_llms_txt_is_blocked() {
    let policy = AdmissionPolicy::deny_all_for_test();
    let intent = InstallIntent::unowned_llms_package_for_test();

    let decision = admission_decision(&policy, &intent);

    assert_eq!(decision.decision.as_str(), "block");
    assert!(
        decision
            .reason_codes
            .iter()
            .any(|reason| reason.as_str() == "artifact_not_approved")
    );
}
