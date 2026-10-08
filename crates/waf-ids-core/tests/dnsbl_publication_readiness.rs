//! Commercial publication readiness must describe emitted evidence, not storage.

use waf_ids_core::{
    AppData, LicenseStatus, ReadinessStatus, SecurityEvent, ThreatFeedStatus,
    buyer_evidence_manifest_at, commercial_readiness_snapshot_at, export_dnsbl_zone,
};

/// Keep every non-publication readiness criterion positive and deterministic.
fn otherwise_ready() -> AppData {
    let mut data = AppData::seeded();
    data.commercial.license_status = LicenseStatus::Active;
    data.commercial.license_id = Some("readiness-fixture".into());
    data.commercial.licensee = Some("fixture buyer".into());
    data.commercial.annual_contract_value_krw = Some(2_000_000_000);
    data.threat_feeds.push(ThreatFeedStatus {
        feed_id: "fixture-feed".into(),
        source: "fixture".into(),
        last_updated_unix: 10,
        threat_count: 1,
        dnsbl_count: 0,
        ttl_seconds: 600,
    });
    data.events.push(SecurityEvent {
        id: 1,
        timestamp_unix: 10,
        client_ip: None,
        route_id: Some("demo".into()),
        action: "monitored".into(),
        reason: "fixture".into(),
        score: 0,
        path: "/demo".into(),
    });
    data
}

#[test]
fn publication_readiness_rejects_nonempty_but_unpublishable_evidence() {
    let positive = otherwise_ready();
    assert!(commercial_readiness_snapshot_at(&positive, 10).ready_for_enterprise_sale);
    assert!(export_dnsbl_zone("dnsbl.example", &positive.dnsbl).contains(" IN A "));
    let seed = positive.dnsbl[0].clone();
    let mut cases = Vec::new();
    let mut entry = seed.clone();
    entry.address = "2001:db8::10".parse().unwrap();
    cases.push(("IPv6-only", entry));
    for ttl in [0, 2_147_483_648, u64::MAX] {
        let mut entry = seed.clone();
        entry.ttl_seconds = ttl;
        cases.push(("invalid TTL", entry));
    }
    for code in ["8.8.8.8", "::1", "not-an-ip"] {
        let mut entry = seed.clone();
        entry.code = code.into();
        cases.push(("invalid answer", entry));
    }
    let mut entry = seed;
    entry.reason = "x".repeat(65_280);
    cases.push(("oversized TXT", entry));
    for (case, entry) in cases {
        let mut data = positive.clone();
        data.dnsbl = vec![entry];
        let original = data.clone();
        assert_eq!(
            export_dnsbl_zone("dnsbl.example", &data.dnsbl)
                .lines()
                .count(),
            2,
            "{case}"
        );
        let readiness = commercial_readiness_snapshot_at(&data, 10);
        assert!(
            !readiness.ready_for_enterprise_sale,
            "{case} advertised sale readiness without emitted records"
        );
        assert_eq!(readiness.blockers, ["dnsbl_publication"], "{case}");
        assert_eq!(
            readiness
                .checks
                .iter()
                .find(|check| check.id == "dnsbl_publication")
                .unwrap()
                .status,
            ReadinessStatus::Fail
        );
        let manifest = buyer_evidence_manifest_at(&data, 10);
        assert!(!manifest.ready_for_enterprise_sale, "{case}");
        assert_eq!(manifest.blockers, ["dnsbl_publication"]);
        assert_eq!(
            manifest.runtime_counts.dnsbl_entry_count, 1,
            "stored-evidence count is not published count"
        );
        assert_eq!(data, original, "{case} mutated stored evidence");
    }
}

#[test]
fn a_publishable_entry_clears_only_the_publication_blocker() {
    let mut data = otherwise_ready();
    let valid = data.dnsbl[0].clone();
    data.dnsbl[0].address = "2001:db8::10".parse().unwrap();
    data.dnsbl.push(valid);
    let original = data.clone();
    let readiness = commercial_readiness_snapshot_at(&data, 10);
    assert!(readiness.ready_for_enterprise_sale);
    assert!(readiness.blockers.is_empty());
    assert_eq!(
        export_dnsbl_zone("dnsbl.example", &data.dnsbl)
            .lines()
            .count(),
        4
    );
    let manifest = buyer_evidence_manifest_at(&data, 10);
    assert!(manifest.ready_for_enterprise_sale);
    assert_eq!(manifest.runtime_counts.dnsbl_entry_count, 2);
    data.commercial.annual_contract_value_krw = None;
    assert_eq!(
        commercial_readiness_snapshot_at(&data, 10).blockers,
        ["contract_value"]
    );
    assert_eq!(&data.dnsbl, &original.dnsbl);
}

#[test]
fn publication_readiness_retains_exporter_boundary_and_legacy_metadata_behavior() {
    let mut data = otherwise_ready();
    data.dnsbl[0].source = "unit".into();
    data.dnsbl[0].reason = "x".repeat(65_279 - " source=unit".len());
    data.dnsbl[0].ttl_seconds = 2_147_483_647;
    let original = data.clone();
    assert!(commercial_readiness_snapshot_at(&data, 10).ready_for_enterprise_sale);
    let zone = export_dnsbl_zone("dnsbl.example", &data.dnsbl);
    assert_eq!(zone.lines().count(), 4);
    assert!(zone.contains("2147483647 IN A "));
    assert_eq!(data, original);

    // Persisted legacy metadata need not satisfy create/import validation to
    // remain safely exportable. Readiness is not a second admission policy.
    for metadata in ["", " ", "\"\\\n\0", "한글😀"] {
        data.dnsbl[0].reason = metadata.into();
        data.dnsbl[0].source = metadata.into();
        data.dnsbl[0].ttl_seconds = 300;
        assert_eq!(
            export_dnsbl_zone("dnsbl.example", &data.dnsbl)
                .lines()
                .count(),
            4
        );
        assert!(commercial_readiness_snapshot_at(&data, 10).ready_for_enterprise_sale);
    }
}
