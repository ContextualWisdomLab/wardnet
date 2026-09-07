# Decision freshness and replay boundary

Wardnet retains `DecisionEnvelopeV1` as security evidence after its live-use window expires. Retention and live admission are therefore separate concerns: `DecisionEnvelopeV1::validate()` validates the bounded serialized contract for archival/audit use, while `DecisionEnvelopeV1::validate_at(now_unix)` first performs the same structural validation and then rejects use before `evaluated_at_unix` or after `expires_at_unix`.

The v1 interval is intentionally inclusive at both endpoints because the surrounding Wardnet v1 validity contracts already use inclusive `valid_from` / `valid_until` semantics. RFC 7519 uses an inclusive not-before boundary but an exclusive expiration boundary for JWT processing. Wardnet does not claim JWT wire compatibility here; the RFC is used only as an authoritative example that live authorization artifacts require explicit current-time acceptance semantics. Changing Wardnet v1 expiry to exclusive would be a wire/behavior contract change and must not be smuggled into this replay repair.

The live validator returns `DecisionLiveValidationErrorV1`. Structural failures are preserved as `Contract(ContractValidationErrorV1)` so callers can distinguish malformed retained evidence from a structurally valid but stale/future decision (`DecisionOutsideValidityWindow`). No wall clock is read inside the domain contract: current time is injected by the caller, keeping tests deterministic and preventing this crate from acquiring runtime/environment authority.

This check is necessary but not sufficient for protected network continuation. A current Wardnet reputation decision is still only one policy authority. EgressWeave remains authoritative for executable URL/address/DNS/peer/redirect/proxy/TLS/resource authorization, and a decision envelope is not proof that transport was blocked or allowed. Authentication of the decision producer and any replay-resistant storage/nonce mechanism remain separate owner/runtime concerns where applicable.

## Traceability

Rose, S., Borchert, O., Mitchell, S., & Connelly, S. (2020). *Zero trust architecture* (NIST Special Publication 800-207). National Institute of Standards and Technology. https://doi.org/10.6028/NIST.SP.800-207

Jones, M., Bradley, J., & Sakimura, N. (2015). *JSON Web Token (JWT)* (RFC 7519). RFC Editor. https://doi.org/10.17487/RFC7519

NIST SP 800-207 supports authorization immediately before resource access rather than relying on prior implicit trust. RFC 7519 Sections 4.1.4 and 4.1.5 provide normative current-time acceptance semantics for time-bounded authorization artifacts. Neither source is treated as authority for Wardnet's transport-neutral schema shape or EgressWeave-owned connection policy.
