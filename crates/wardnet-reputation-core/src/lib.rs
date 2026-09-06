//! Pure Wardnet outbound site-reputation contracts.
//!
//! This crate deliberately performs no HTTP, DNS, transport authorization, database I/O,
//! environment access, or LLM work. Executable outbound target interpretation remains an
//! EgressWeave responsibility; this crate only accepts already-canonical offline descriptors.
//!
//! The research, standards, rejected alternatives, and evidence-handling rationale for this
//! contract boundary are recorded in the adjacent [TRACEABILITY.md](../TRACEABILITY.md).

pub mod model;

pub use model::*;
