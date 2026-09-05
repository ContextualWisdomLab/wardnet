#[path = "../src/misp_import.rs"]
mod misp_import;

#[test]
fn malformed_or_missing_to_ids_values_fail_closed() {
    // Policy and research traceability: docs/doctoring/misp-to-ids-admission.md.
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

#[test]
fn deleted_misp_attributes_cannot_authorize_enforcement() {
    // A positive `to_ids` signal cannot resurrect an attribute MISP marks deleted.
    let raw = r#"[
      {"type":"domain","value":"deleted-bool.example","to_ids":true,"deleted":true},
      {"type":"domain","value":"deleted-string.example","to_ids":true,"deleted":"1"},
      {"type":"domain","value":"malformed-deleted.example","to_ids":true,"deleted":{"unexpected":false}},
      {"type":"domain","value":"active-bool.example","to_ids":true,"deleted":false},
      {"type":"domain","value":"active-string.example","to_ids":true,"deleted":"0"},
      {"type":"domain","value":"active-omitted.example","to_ids":true}
    ]"#;

    let material = misp_import::parse_misp_document(raw, "misp:test", 60).unwrap();

    assert_eq!(material.threats.len(), 3);
    assert!(
        material
            .threats
            .iter()
            .any(|threat| threat.value == "active-bool.example")
    );
    assert!(
        material
            .threats
            .iter()
            .any(|threat| threat.value == "active-string.example")
    );
    assert!(
        material
            .threats
            .iter()
            .any(|threat| threat.value == "active-omitted.example")
    );
    assert_eq!(material.skipped_attributes, 3);
}

#[test]
fn deleted_or_ambiguous_misp_objects_cannot_authorize_nested_attributes() {
    // MISP objects carry an independent lifecycle marker. A nested attribute's
    // `to_ids=true` cannot override a deleted or structurally ambiguous parent object.
    let raw = r#"{
      "Event": {
        "id": "object-lifecycle",
        "Object": [
          {
            "name": "deleted-bool",
            "deleted": true,
            "Attribute": [
              {"type":"domain","value":"deleted-object-bool.example","to_ids":true,"deleted":false}
            ]
          },
          {
            "name": "deleted-string",
            "deleted": "1",
            "Attribute": [
              {"type":"domain","value":"deleted-object-string.example","to_ids":true}
            ]
          },
          {
            "name": "ambiguous-object",
            "deleted": {"unexpected": false},
            "Attribute": [
              {"type":"domain","value":"ambiguous-object.example","to_ids":true}
            ]
          },
          {
            "name": "active-bool",
            "deleted": false,
            "Attribute": [
              {"type":"domain","value":"active-object-bool.example","to_ids":true}
            ]
          },
          {
            "name": "active-omitted",
            "Attribute": [
              {"type":"domain","value":"active-object-omitted.example","to_ids":true}
            ]
          }
        ]
      }
    }"#;

    let material = misp_import::parse_misp_document(raw, "misp:test", 60).unwrap();

    assert_eq!(material.threats.len(), 2);
    assert!(
        material
            .threats
            .iter()
            .any(|threat| threat.value == "active-object-bool.example")
    );
    assert!(
        material
            .threats
            .iter()
            .any(|threat| threat.value == "active-object-omitted.example")
    );
    assert_eq!(material.skipped_attributes, 3);
}
