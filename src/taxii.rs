//! TAXII 2.1 collection poll helpers.
//!
//! Operators provide a TAXII 2.1 **objects** URL (or API root + collection id).
//! The poll response is normalized into STIX JSON that
//! [`crate::stix_import::parse_stix_document`] already understands.
//! This is a proven threat-intel transport boundary — not a detection engine.

/// Build a TAXII 2.1 collection objects URL from an API root and collection id.
pub fn collection_objects_url(api_root: &str, collection_id: &str) -> Result<String, String> {
    let root = api_root.trim().trim_end_matches('/');
    let id = collection_id.trim().trim_matches('/');
    if root.is_empty() {
        return Err("api_root must be non-empty".to_string());
    }
    if id.is_empty() {
        return Err("collection_id must be non-empty".to_string());
    }
    if id.contains('/') || id.contains('?') || id.contains('#') {
        return Err("collection_id must not contain path or query characters".to_string());
    }
    Ok(format!("{root}/collections/{id}/objects/"))
}

/// Append optional TAXII filter query parameters to an objects URL.
pub fn with_taxii_filters(objects_url: &str, added_after: Option<&str>) -> Result<String, String> {
    let base = objects_url.trim();
    if base.is_empty() {
        return Err("objects_url must be non-empty".to_string());
    }
    let Some(after) = added_after.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(base.to_string());
    };
    // Reject characters that would break out of a single query value.
    if after
        .chars()
        .any(|c| c.is_control() || c == '&' || c == '#')
    {
        return Err("added_after contains invalid characters".to_string());
    }
    let mut url =
        reqwest::Url::parse(base).map_err(|error| format!("invalid objects_url: {error}"))?;
    url.query_pairs_mut().append_pair("added_after", after);
    Ok(url.to_string())
}

/// Normalize a TAXII 2.1 objects response (or raw STIX) into STIX JSON text.
///
/// Accepts:
/// - STIX Bundle (`type=bundle`)
/// - STIX Indicator
/// - JSON array of STIX objects
/// - TAXII 2.1 envelope `{ "objects": [ ... ], "more": false }`
pub fn stix_json_from_taxii_response(body: &str) -> Result<String, String> {
    let trimmed = body.trim();
    if trimmed.is_empty() {
        return Err("empty TAXII response body".to_string());
    }
    let value: serde_json::Value = serde_json::from_str(trimmed)
        .map_err(|error| format!("invalid TAXII/STIX JSON: {error}"))?;

    match &value {
        // Already a STIX document the importer accepts.
        obj if obj.get("type").and_then(|t| t.as_str()) == Some("bundle")
            || obj.get("type").and_then(|t| t.as_str()) == Some("indicator") =>
        {
            Ok(trimmed.to_string())
        }
        serde_json::Value::Array(_) => Ok(trimmed.to_string()),
        // TAXII 2.1 envelope: wrap objects into a synthetic STIX bundle.
        obj if obj.get("objects").and_then(|o| o.as_array()).is_some() => {
            let objects = obj.get("objects").cloned().unwrap_or(serde_json::json!([]));
            if objects.as_array().map(|a| a.is_empty()).unwrap_or(true) {
                return Err("TAXII envelope contained no objects".to_string());
            }
            let bundle = serde_json::json!({
                "type": "bundle",
                "id": "bundle--taxii-poll",
                "objects": objects,
            });
            serde_json::to_string(&bundle)
                .map_err(|error| format!("failed to serialize STIX bundle: {error}"))
        }
        _ => Err(
            "TAXII response must be a STIX bundle/indicator/array or a TAXII objects envelope"
                .to_string(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_collection_objects_url() {
        assert_eq!(
            collection_objects_url("https://taxii.example/api1/", "abc-123").unwrap(),
            "https://taxii.example/api1/collections/abc-123/objects/"
        );
        assert!(collection_objects_url("https://x/", "../evil").is_err());
    }

    #[test]
    fn normalizes_taxii_envelope_to_bundle() {
        let body = r#"{
          "more": false,
          "objects": [
            {
              "type": "indicator",
              "id": "indicator--aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
              "pattern": "[ipv4-addr:value = '203.0.113.50']",
              "pattern_type": "stix",
              "valid_from": "2024-01-01T00:00:00Z"
            }
          ]
        }"#;
        let stix = stix_json_from_taxii_response(body).unwrap();
        let value: serde_json::Value = serde_json::from_str(&stix).unwrap();
        assert_eq!(value["type"], "bundle");
        assert_eq!(value["objects"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn passes_through_stix_bundle() {
        let body = r#"{"type":"bundle","id":"bundle--1","objects":[]}"#;
        // Empty objects still passes through; STIX importer will reject later.
        let stix = stix_json_from_taxii_response(body).unwrap();
        assert!(stix.contains("bundle"));
    }

    #[test]
    fn rejects_empty_and_garbage() {
        assert!(stix_json_from_taxii_response("").is_err());
        assert!(stix_json_from_taxii_response("not-json").is_err());
        assert!(stix_json_from_taxii_response(r#"{"foo":1}"#).is_err());
        assert!(stix_json_from_taxii_response(r#"{"objects":[]}"#).is_err());
    }

    #[test]
    fn adds_added_after_query() {
        let url = with_taxii_filters(
            "https://taxii.example/api1/collections/c/objects/",
            Some("2024-01-01T00:00:00Z"),
        )
        .unwrap();
        assert!(url.contains("added_after="));
        assert!(url.contains("2024"));
    }
}
