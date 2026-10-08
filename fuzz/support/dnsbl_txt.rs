//! Reuse the crate-local test oracle without exporting a production API.

#[path = "../../crates/waf-ids-core/tests/support/dnsbl_txt.rs"]
mod oracle;

pub use oracle::{assert_zone_txt_valid, decode_txt_rdata};
