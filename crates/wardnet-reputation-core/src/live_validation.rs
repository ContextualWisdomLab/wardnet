//! Live-use validation for retained reputation decision envelopes.
//!
//! Structural validation remains on [`DecisionEnvelopeV1::validate`]. This module adds the
//! separate current-time admission check needed by a live consumer so retained audit evidence can
//! remain structurally inspectable after expiry without being reusable as current authorization.
//!
//! Security rationale and standards traceability are recorded in
//! [DECISION_FRESHNESS.md](../DECISION_FRESHNESS.md).

use crate::model::{ContractValidationErrorV1, DecisionEnvelopeV1};

/// Fail-closed errors returned when a structurally valid decision is evaluated for live reuse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecisionLiveValidationErrorV1 {
    /// The retained envelope is structurally invalid under the v1 contract.
    Contract(ContractValidationErrorV1),
    /// The current instant is before evaluation or after the inclusive expiry instant.
    DecisionOutsideValidityWindow,
}

impl From<ContractValidationErrorV1> for DecisionLiveValidationErrorV1 {
    fn from(error: ContractValidationErrorV1) -> Self {
        Self::Contract(error)
    }
}

impl DecisionEnvelopeV1 {
    /// Validate the envelope for live use at an injected current time.
    ///
    /// The evaluation and expiry instants are inclusive. Callers that retain historical evidence
    /// should continue to use [`DecisionEnvelopeV1::validate`] when they only need structural
    /// validation and must not treat a structurally valid historical record as a current grant.
    pub fn validate_at(&self, now_unix: u64) -> Result<(), DecisionLiveValidationErrorV1> {
        self.validate()?;
        if now_unix < self.evaluated_at_unix || now_unix > self.expires_at_unix {
            return Err(DecisionLiveValidationErrorV1::DecisionOutsideValidityWindow);
        }
        Ok(())
    }
}
