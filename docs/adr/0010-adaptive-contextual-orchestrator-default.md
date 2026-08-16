# ADR-0010: SOC analysis delegates default execution to contextual-orchestrator auto

- Status: Accepted
- Date: 2026-08-16

## Context

Wardnet's optional SOC analysis endpoint calls the organization LLM gateway, but a
model/messages-only request leaves policy implicit and can collapse into a fixed
single-worker path. Security analysis ranges from short enrichment to high-risk,
multi-step investigation; the application should not hard-code one model or one
workflow for all cases.

## Decision

The SOC request explicitly includes `orchestration_mode: "auto"`. The central
orchestrator selects the quality-sufficient route, worker-plus-verifier path, or
conducted workflow; known lower cost is used only after capability and safety
requirements. Unpriced providers are not treated as free.

Wardnet retains WAF/IDS evidence collection, authorization, bounded request handling,
audit records, security-domain validation, and operator presentation. Explicit fixed
modes remain controlled orchestration experiments and rollback controls, not the
product default.

## References

Omidvar, H., & Akhlaghi, V. (2026). *A communication-theoretic framework for LLM agents: Cost-aware adaptive reliability* [Preprint]. arXiv. https://doi.org/10.48550/arXiv.2605.09121

Tang, Y., Cetin, E., Xu, J., Sun, Q., Nielsen, S., Richard, V., Goda, H., Tymchenko, I., Nguyen, N., Lee, H., Ashiga, M., Kotyan, S., Kuroki, S., & Clanuwat, T. (2026). *Sakana Fugu technical report* [Technical report]. arXiv. https://doi.org/10.48550/arXiv.2606.21228
