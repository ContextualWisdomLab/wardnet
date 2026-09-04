#[path = "../src/misp_import.rs"]
mod misp_import;

#[test]
fn malformed_or_missing_to_ids_values_fail_closed() {
    let raw = r#"[
      {"type":"domain","value":"object.example","to_ids":{"unexpected":true}},
      {"type":"domain","value":"array.example","to_ids":[true]},
      {"type":"domain","value":"null.example","to_ids":null},
      {"type":"domain","value":"missing.example"},
      {"type":"domain","value":"valid.example","to_ids":true}
    ]"#;

    let material = misp_import::parse_misp_document(raw, "misp:test", 60).unwrap();

    assert_eq!(material.threats.len(), 1);
    assert_eq!(material.threats[0].value, "valid.example");
    assert_eq!(material.skipped_attributes, 4);
}
