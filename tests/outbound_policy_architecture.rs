use std::{fs, path::PathBuf};

fn production_lib_source() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/lib.rs");
    fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!(
            "failed to read production source {}: {error}",
            path.display()
        )
    })
}

fn source_section<'a>(source: &'a str, start_marker: &str, end_marker: &str) -> &'a str {
    let start = source
        .find(start_marker)
        .unwrap_or_else(|| panic!("missing source marker {start_marker:?}"));
    let relative_end = source[start..]
        .find(end_marker)
        .unwrap_or_else(|| panic!("missing source boundary {end_marker:?}"));
    &source[start..start + relative_end]
}

#[test]
fn outbound_http_client_construction_stays_behind_the_shared_fail_closed_builder() {
    let source = production_lib_source();

    assert!(
        !source.contains("reqwest::Client::new("),
        "production code must not introduce a raw reqwest Client that bypasses the shared outbound policy"
    );
    assert!(
        !source.contains("reqwest::Client::default("),
        "production code must not introduce a default reqwest Client that follows redirects or ambient proxies"
    );
    assert_eq!(
        source.matches("reqwest::Client::builder()").count(),
        1,
        "all outbound reqwest Client construction must remain centralized in outbound_http_client_builder"
    );
    assert!(
        !source.contains("state.http.") && !source.contains("state.feed_http."),
        "shared clients may only be supplied to validated_outbound_http_client, never used directly for outbound I/O"
    );

    let builder = source_section(
        &source,
        "fn outbound_http_client_builder()",
        "#[derive(Debug, Clone)]\npub struct AppConfig",
    );
    assert!(
        builder.contains("redirect(reqwest::redirect::Policy::none())"),
        "the shared outbound client must fail closed on redirects"
    );
    assert!(
        builder.contains(".no_proxy()"),
        "the shared outbound client must ignore ambient proxy configuration"
    );
}

#[test]
fn represented_outbound_surfaces_revalidate_destinations_before_network_io() {
    let source = production_lib_source();
    let mediated_surfaces = [
        (
            "async fn clearfolio_submit(",
            "async fn clearfolio_status(",
            "clearfolio_submit",
        ),
        (
            "async fn clearfolio_status(",
            "async fn soc_analyze(",
            "clearfolio_status",
        ),
        (
            "async fn soc_analyze(",
            "async fn create_route(",
            "soc_analyze",
        ),
        (
            "async fn fetch_taxii_objects(",
            "/// Ingest Suricata EVE",
            "fetch_taxii_objects",
        ),
        (
            "async fn fetch_text_feed(",
            "fn parse_phishing_domains(",
            "fetch_text_feed",
        ),
        (
            "async fn fetch_kev_catalog(",
            "/// Returns whether the parsed host is localhost",
            "fetch_kev_catalog",
        ),
        (
            "async fn proxy_request(",
            "pub fn upstream_target(",
            "proxy_request",
        ),
    ];

    for (start_marker, end_marker, function_name) in mediated_surfaces {
        let body = source_section(&source, start_marker, end_marker);
        assert!(
            body.contains("validated_outbound_http_client"),
            "{function_name} must obtain its HTTP client through the request-time outbound destination policy"
        );
    }
}

#[test]
fn phishing_feed_dns_resolution_shares_the_end_to_end_operation_deadline() {
    let source = production_lib_source();
    let resolver = source_section(
        &source,
        "async fn validated_outbound_http_client(",
        "fn pinned_outbound_http_client(",
    );

    assert!(
        resolver.contains("tokio::time::Instant") && resolver.contains("tokio::time::timeout_at("),
        "manual DNS resolution must accept an operation deadline and fail closed at that same deadline"
    );

    for (start_marker, end_marker, function_name) in [
        (
            "async fn fetch_taxii_objects(",
            "/// Ingest Suricata EVE",
            "fetch_taxii_objects",
        ),
        (
            "async fn fetch_text_feed(",
            "fn parse_phishing_domains(",
            "fetch_text_feed",
        ),
        (
            "async fn fetch_kev_catalog(",
            "/// Returns whether the parsed host is localhost",
            "fetch_kev_catalog",
        ),
    ] {
        let body = source_section(&source, start_marker, end_marker);
        assert!(
            body.contains("tokio::time::Instant")
                && body.contains("validated_outbound_http_client")
                && body.contains(".timeout("),
            "{function_name} must establish one deadline before DNS validation and apply only the remaining budget to the HTTP request"
        );
    }
}
