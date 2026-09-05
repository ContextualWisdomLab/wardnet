#[path = "../src/misp_import.rs"]
mod misp_import;

use waf_ids_core::Severity;

fn admitted_event(threat_level_id: &str, value: &str) -> String {
    format!(
        r#"{{"Event":{{"id":"severity-contract","threat_level_id":{threat_level_id},"Attribute":[{{"type":"domain","value":"{value}","to_ids":true,"deleted":false}}]}}}}"#
    )
}

#[test]
fn misp_defined_threat_levels_preserve_source_severity() {
    // MISP threat_level_id is 1=High, 2=Medium, 3=Low. The adapter must not
    // promote source severity while translating an admitted external fact.
    let cases = [
        (r#""1""#, "high.example", Severity::High),
        ("2", "medium.example", Severity::Medium),
        (r#""3""#, "low.example", Severity::Low),
    ];

    for (threat_level_id, value, expected) in cases {
        let raw = admitted_event(threat_level_id, value);
        let material = misp_import::parse_misp_document(&raw, "misp:test", 60).unwrap();
        assert_eq!(material.threats.len(), 1);
        assert_eq!(material.threats[0].value, value);
        assert_eq!(material.threats[0].severity, expected);
    }
}

#[test]
fn undefined_and_missing_misp_levels_do_not_invent_stronger_source_truth() {
    let undefined = admitted_event("4", "undefined.example");
    let undefined_material =
        misp_import::parse_misp_document(&undefined, "misp:test", 60).unwrap();
    assert_eq!(undefined_material.threats[0].severity, Severity::Low);

    let missing = r#"{"Event":{"id":"severity-contract","Attribute":[{"type":"domain","value":"missing.example","to_ids":true,"deleted":false}]}}"#;
    let missing_material = misp_import::parse_misp_document(missing, "misp:test", 60).unwrap();
    assert_eq!(missing_material.threats[0].severity, Severity::Medium);
}
