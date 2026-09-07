use waf_ids_core::{select_route, EnforcementMode, RouteConfig};

fn route(id: &str, path_prefix: &str, enabled: bool) -> RouteConfig {
    RouteConfig {
        id: id.to_string(),
        path_prefix: path_prefix.to_string(),
        upstream: format!("mock://{id}"),
        mode: EnforcementMode::Block,
        enabled,
        block_threshold: Some(50),
    }
}

#[test]
fn route_prefix_matches_only_exact_path_or_descendant_segment() {
    let routes = vec![route("api", "/api", true)];

    assert_eq!(
        select_route(&routes, "/api").map(|route| route.id.as_str()),
        Some("api")
    );
    assert_eq!(
        select_route(&routes, "/api/items").map(|route| route.id.as_str()),
        Some("api")
    );

    assert!(
        select_route(&routes, "/apix").is_none(),
        "a lexical sibling must not inherit /api routing, enforcement, or upstream authority"
    );
    assert!(
        select_route(&routes, "/api-v2").is_none(),
        "a delimiter other than '/' must not create a descendant path segment"
    );
}

#[test]
fn narrower_route_cannot_capture_a_sibling_path_segment() {
    let routes = vec![
        route("api", "/api", true),
        route("admin", "/api/admin", true),
    ];

    assert_eq!(
        select_route(&routes, "/api/admin/users")
            .map(|route| route.id.as_str()),
        Some("admin")
    );
    assert_eq!(
        select_route(&routes, "/api/administrator")
            .map(|route| route.id.as_str()),
        Some("api"),
        "the /api/admin route must not capture the sibling /api/administrator segment"
    );
}

#[test]
fn root_and_trailing_slash_prefixes_keep_existing_hierarchical_semantics() {
    let root_only = vec![route("root", "/", true)];
    assert_eq!(
        select_route(&root_only, "/anything/here")
            .map(|route| route.id.as_str()),
        Some("root")
    );

    let routes = vec![
        route("root", "/", true),
        route("api", "/api/", true),
        route("disabled", "/api/admin", false),
    ];
    assert_eq!(
        select_route(&routes, "/api/items").map(|route| route.id.as_str()),
        Some("api")
    );
    assert_eq!(
        select_route(&routes, "/api/admin/users")
            .map(|route| route.id.as_str()),
        Some("api"),
        "disabled narrower routes must remain ignored"
    );
}
