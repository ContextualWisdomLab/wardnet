//! Fuzz-only access to the package-local independent publication oracle.

#[path = "../../crates/waf-ids-core/tests/support/dnsbl_zone.rs"]
mod oracle;

pub use oracle::{assert_zone_matches_entries, dnsbl_txt, metadata_fits_rdata};
