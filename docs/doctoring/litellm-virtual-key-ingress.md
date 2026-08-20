# LiteLLM virtual-key ingress: standards traceability

## Engineering claim

A dedicated Rust reverse proxy rejects missing, duplicate, non-Bearer, and clearly non-LiteLLM credentials before upstream I/O while preserving LiteLLM as the authoritative authentication and authorization system.

## Traceability

| External requirement | Product decision | Implementation evidence | Test evidence |
|---|---|---|---|
| OAuth 2.0 bearer tokens are carried in the `Authorization` header using the `Bearer` scheme | Require exactly one Bearer header; emit an RFC 6750 challenge on failure | `src/credential_guard.rs` | guard unit tests and `tests/litellm_virtual_key_guard.rs` |
| A proxy must remove or consume hop-by-hop connection metadata rather than blindly forwarding it | Use an explicit end-to-end request/response header allowlist | `forward_request_headers`, `copy_response_headers` | upstream-capture regression verifies cookie stripping and required metadata |
| Authentication failures must not disclose credentials | Emit stable reason codes only; no submitted value in JSON, structured events, or challenges | `CredentialRejection`, `rejection_response`, `emit_auth_rejection` | phone-shaped canary is absent from the response; upstream hit count stays zero |
| Security controls should fail closed before crossing a trust boundary | Apply the credential-class guard before target construction and upstream transport | `src/litellm_guard_proxy.rs` | missing, duplicate, wrong-scheme, and phone-shaped credentials never reach the loopback upstream |
| A lexical prefilter must not replace authoritative key validation | Accept only the expected credential class, then delegate existence/revocation/budget/scope to LiteLLM | ADR-0011 | valid-shaped test proves forwarding, not local authentication |
| Intermediaries must not blindly propagate connection-specific or sensitive metadata | Fixed request/response header projection; cookies, host, proxy credentials, forwarding chain, and transfer framing omitted | `src/credential_guard.rs` | valid request reaches upstream without the supplied cookie |
| A fixed upstream credential boundary must not follow an unvalidated redirect | Disable redirects in the pooled `reqwest` client | `ProxyState::new` | configuration and transport contract tests |
| Streaming LLM responses should not require whole-body buffering | Construct the downstream Axum body from the upstream byte stream | `src/litellm_guard_proxy.rs` | SSE content type, body, query, correlation, and rate-limit metadata round trip |

## Security interpretation

The `sk-` prefix is a **credential-class discriminator**, not proof of identity. This design prevents a known wrong class, such as a phone-shaped value, from entering LiteLLM's authentication path. It intentionally does not make a local key database, guess whether a virtual key is active, or duplicate LiteLLM's team, model, budget, and scope semantics.

The upstream URL is operator-owned rather than caller-owned. The first release requires HTTPS except loopback tests, rejects URL credentials/query/fragment, and disables redirects. Resolved-address policy, DNS rebinding resistance, and connection-time peer verification remain additional defense-in-depth work for deployments whose configuration authority is not already trusted.

## APA 7 references

Internet Engineering Task Force. (2012). *The OAuth 2.0 authorization framework: Bearer token usage* (RFC 6750). https://doi.org/10.17487/RFC6750

Internet Engineering Task Force. (2022). *HTTP semantics* (RFC 9110). https://doi.org/10.17487/RFC9110

National Institute of Standards and Technology. (2022). *Secure software development framework (SSDF) version 1.1: Recommendations for mitigating the risk of software vulnerabilities* (NIST Special Publication 800-218). https://doi.org/10.6028/NIST.SP.800-218

OWASP Foundation. (2025). *OWASP application security verification standard 5.0.0*. https://owasp.org/www-project-application-security-verification-standard/
