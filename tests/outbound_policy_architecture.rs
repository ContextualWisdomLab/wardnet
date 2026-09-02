use std::{fs, path::PathBuf};

fn production_lib_source() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/lib.rs");
    fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!("failed to read production source {}: {error}", path.display())
    })
}

fn function_body<'a>(source: &'a str, function_name: &str, next_function_name: &str) -> &'a str {
    let start_marker = format!("fn {function_name}(");
    let async_start_marker = format!("async fn {function_name}(");
    let start = source
        .find(&async_start_marker)
        .or_else(|| source.find(&start_marker))
        .unwrap_or_else(|| panic!("missing production function {function_name}"));

    let next_marker = format!("fn {next_function_name}(");
    let async_next_marker = format!("async fn {next_function_name}(");
    let relative_end = source[start..]
        .find(&async_next_marker)
        .or_else(|| source[start..].find(&next_marker))
        .unwrap_or_else(|| panic!("missing boundary function {next_function_name}"));

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

    let builder = function_body(
        &source,
        "outbound_http_client_builder",
        "clearfolio_tenant_headers",
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
        ("clearfolio_submit", "clearfolio_status"),
        ("clearfolio_status", "soc_analyze"),
        ("soc_analyze", "create_route"),
        ("fetch_taxii_objects", "import_taxii_feed"),
        ("fetch_text_feed", "import_phishing_database_feed"),
        ("fetch_kev_catalog", "is_loopback_host"),
        ("proxy_request", "build_proxy_url"),
    ];

    for (function_name, next_function_name) in mediated_surfaces {
        let body = function_body(&source, function_name, next_function_name);
        assert!(
            body.contains("validated_outbound_http_client"),
            "{function_name} must obtain its HTTP client through the request-time outbound destination policy"
        );
    }
}
