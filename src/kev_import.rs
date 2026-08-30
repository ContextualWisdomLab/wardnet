//! CISA Known Exploited Vulnerabilities (KEV) catalog import adapter.
//!
//! Parses the CISA KEV catalog JSON
//! (<https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json>)
//! into gateway [`ThreatIndicator`] rows. This is a proven federal
//! authoritative-source boundary — not a hand-rolled detection engine.
//!
//! The catalog is CVE-centric: entries carry no IP/domain/URL/hash
//! observable, so `dnsbl` stays empty. It is kept on [`KevImportMaterial`]
//! only for parity with the shared [`waf_ids_core::ThreatFeedImport`] shape
//! every adapter in this family produces.

use waf_ids_core::{DnsblEntry, Severity, ThreatIndicator};

/// Parsed KEV import ready for the existing threat-feed upsert path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KevImportMaterial {
    pub threats: Vec<ThreatIndicator>,
    pub dnsbl: Vec<DnsblEntry>,
    pub skipped_entries: usize,
}

/// Extract CVE indicators from a CISA KEV catalog JSON document.
///
/// Accepts the real catalog shape (`{"vulnerabilities": [...], ...}`) or a
/// bare JSON array of vulnerability entries.
pub fn kev_material_from_value(
    value: &serde_json::Value,
    source: &str,
    ttl_seconds: u64,
) -> Result<KevImportMaterial, String> {
    let entries = match value {
        serde_json::Value::Object(_) => value
            .get("vulnerabilities")
            .and_then(|v| v.as_array())
            .ok_or("KEV document must have a \"vulnerabilities\" array")?,
        serde_json::Value::Array(items) => items,
        _ => {
            return Err(
                "KEV document must be a catalog object or an array of vulnerability entries"
                    .to_string(),
            );
        }
    };
    if entries.is_empty() {
        return Err("KEV catalog contained no vulnerability entries".to_string());
    }

    let mut threats = Vec::new();
    let mut skipped_entries = 0usize;
    for entry in entries {
        match kev_entry_outcome(entry, source, ttl_seconds) {
            KevEntryOutcome::Mapped(threat) => threats.push(threat),
            KevEntryOutcome::Skipped => skipped_entries += 1,
        }
    }

    if threats.is_empty() {
        return Err("no KEV entries carried a usable cveID".to_string());
    }

    Ok(KevImportMaterial {
        threats,
        dnsbl: Vec::new(),
        skipped_entries,
    })
}

/// Parse a CISA KEV catalog JSON body string.
pub fn parse_kev_document(
    body: &str,
    source: &str,
    ttl_seconds: u64,
) -> Result<KevImportMaterial, String> {
    let trimmed = body.trim();
    if trimmed.is_empty() {
        return Err("empty KEV catalog body".to_string());
    }
    let value: serde_json::Value =
        serde_json::from_str(trimmed).map_err(|error| format!("invalid KEV JSON: {error}"))?;
    kev_material_from_value(&value, source, ttl_seconds)
}

enum KevEntryOutcome {
    Mapped(ThreatIndicator),
    Skipped,
}

fn kev_entry_outcome(entry: &serde_json::Value, source: &str, ttl_seconds: u64) -> KevEntryOutcome {
    let Some(cve_id) = entry
        .get("cveID")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
    else {
        return KevEntryOutcome::Skipped;
    };

    // CISA's own inclusion criteria (confirmed active exploitation in the
    // wild) already implies high severity; entries CISA has additionally
    // tied to a known ransomware campaign are escalated to critical.
    let known_ransomware = entry
        .get("knownRansomwareCampaignUse")
        .and_then(|v| v.as_str())
        .is_some_and(|s| s.eq_ignore_ascii_case("known"));
    let severity = if known_ransomware {
        Severity::Critical
    } else {
        Severity::High
    };

    KevEntryOutcome::Mapped(ThreatIndicator {
        value: cve_id.to_ascii_uppercase(),
        indicator_type: "cve".to_string(),
        severity,
        source: source.to_string(),
        ttl_seconds,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_catalog() -> &'static str {
        r#"{
          "title": "CISA Catalog of Known Exploited Vulnerabilities",
          "catalogVersion": "2026.08.27",
          "dateReleased": "2026-08-27T17:00:36.6632Z",
          "count": 2,
          "vulnerabilities": [
            {
              "cveID": "cve-2023-49105",
              "vendorProject": "ownCloud",
              "product": "ownCloud",
              "vulnerabilityName": "ownCloud Improper Authentication Vulnerability",
              "dateAdded": "2026-08-27",
              "shortDescription": "ownCloud contains an improper authentication vulnerability.",
              "requiredAction": "Apply mitigations in accordance with vendor instructions.",
              "dueDate": "2026-08-30",
              "knownRansomwareCampaignUse": "Unknown",
              "notes": "https://owncloud.org/security",
              "cwes": ["CWE-287"]
            },
            {
              "cveID": "CVE-2021-44228",
              "vendorProject": "Apache",
              "product": "Log4j2",
              "vulnerabilityName": "Apache Log4j2 Remote Code Execution Vulnerability",
              "dateAdded": "2021-12-10",
              "shortDescription": "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP.",
              "requiredAction": "Apply mitigations in accordance with vendor instructions.",
              "dueDate": "2021-12-24",
              "knownRansomwareCampaignUse": "Known",
              "notes": "",
              "cwes": ["CWE-917", "CWE-400"]
            }
          ]
        }"#
    }

    #[test]
    fn maps_catalog_entries_and_escalates_ransomware_severity() {
        let material = parse_kev_document(sample_catalog(), "feed:cisa-kev", 86_400).unwrap();
        assert_eq!(material.threats.len(), 2);
        assert!(material.dnsbl.is_empty());
        assert_eq!(material.skipped_entries, 0);

        let owncloud = material
            .threats
            .iter()
            .find(|t| t.value == "CVE-2023-49105")
            .expect("owncloud CVE normalized to uppercase");
        assert_eq!(owncloud.indicator_type, "cve");
        assert_eq!(owncloud.severity, Severity::High);
        assert_eq!(owncloud.source, "feed:cisa-kev");
        assert_eq!(owncloud.ttl_seconds, 86_400);

        let log4j = material
            .threats
            .iter()
            .find(|t| t.value == "CVE-2021-44228")
            .expect("log4j CVE present");
        assert_eq!(log4j.severity, Severity::Critical);
    }

    #[test]
    fn accepts_bare_array_of_entries() {
        let raw = r#"[{"cveID":"CVE-2024-0001","knownRansomwareCampaignUse":"Unknown"}]"#;
        let material = parse_kev_document(raw, "feed:cisa-kev", 3600).unwrap();
        assert_eq!(material.threats.len(), 1);
        assert_eq!(material.threats[0].value, "CVE-2024-0001");
    }

    #[test]
    fn skips_entries_missing_cve_id() {
        let raw = r#"{"vulnerabilities": [
          {"vendorProject": "NoId Inc", "knownRansomwareCampaignUse": "Unknown"},
          {"cveID": "CVE-2024-9999", "knownRansomwareCampaignUse": "Unknown"}
        ]}"#;
        let material = parse_kev_document(raw, "feed:cisa-kev", 3600).unwrap();
        assert_eq!(material.threats.len(), 1);
        assert_eq!(material.skipped_entries, 1);
    }

    #[test]
    fn rejects_empty_and_non_kev_documents() {
        assert!(parse_kev_document("", "s", 60).is_err());
        assert!(parse_kev_document("not-json", "s", 60).is_err());
        assert!(parse_kev_document(r#"{"foo":1}"#, "s", 60).is_err());
        assert!(parse_kev_document(r#"{"vulnerabilities": []}"#, "s", 60).is_err());
        assert!(
            parse_kev_document(r#"{"vulnerabilities": [{"vendorProject":"x"}]}"#, "s", 60).is_err()
        );
    }

    #[test]
    fn parse_never_panics_on_arbitrary_text() {
        for sample in ["", "{", "[]", "null", "\0", "{\"vulnerabilities\":[]}"] {
            let _ = parse_kev_document(sample, "s", 60);
        }
    }
}
