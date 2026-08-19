const RECORD: &str = include_str!("../docs/production-readiness.json");
const REPORT: &str = include_str!("../docs/production-readiness.md");

const AUDITED_COMMIT: &str = "b53dc7a1b8904a16752abbdc04429df893a4e32e";
const REQUIRED_ISSUES: &[u32] = &[
    11, 72, 74, 75, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87,
];

#[test]
fn production_claim_is_blocked_on_the_audited_main_commit() {
    assert!(RECORD.contains("\"overall_status\": \"blocked\""));
    assert!(RECORD.contains("\"production_claim_allowed\": false"));
    assert!(RECORD.contains(AUDITED_COMMIT));
    assert!(REPORT.contains("NOT PRODUCTION READY"));
    assert!(REPORT.contains(AUDITED_COMMIT));
}

#[test]
fn every_mandatory_gate_is_linked_in_both_records() {
    for issue in REQUIRED_ISSUES {
        let url = format!("https://github.com/ContextualWisdomLab/wardnet/issues/{issue}");
        assert!(RECORD.contains(&url), "machine record omits {url}");
        assert!(REPORT.contains(&format!("#{issue}")), "report omits issue #{issue}");
    }
}

#[test]
fn readiness_record_contains_no_placeholder_or_premature_success_claim() {
    for forbidden in [
        "TBD",
        "TODO",
        "replace-me",
        "replace-with-secret-manager-sync",
        "\"overall_status\": \"production\"",
        "\"production_claim_allowed\": true",
    ] {
        assert!(!RECORD.contains(forbidden), "record contains forbidden marker {forbidden}");
    }
}
