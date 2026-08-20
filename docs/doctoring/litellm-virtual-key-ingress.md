# LiteLLM virtual-key ingress: standards traceability

## Engineering claim

A route-level proxy guard rejects missing, duplicate, non-Bearer, and clearly non-LiteLLM credentials before upstream I/O while preserving LiteLLM as the authoritative authentication and authorization system.

## Traceability

| External requirement | Product decision | Implementation evidence | Test evidence |
|---|---|---|---|
| OAuth 2.0 bearer tokens are carried in the `Authorization` header using the `Bearer` scheme | Require exactly one Bearer header; emit an RFC 6750 challenge on failure | `src/credential_guard.rs` | guard unit tests and `tests/litellm_virtual_key_guard.rs` |
| A proxy must remove or consume hop-by-hop connection metadata rather than blindly forwarding it | Use an explicit end-to-end request/response header allowlist | `forward_request_headers`, `copy_response_headers` | upstream-capture regression verifies cookie stripping and required metadata |
| Authentication failures must not disclose credentials | Emit stable reason codes only; no submitted value in JSON, events, logs, or challenge | `CredentialRejection`, `rejection_response` | phone-shaped canary is absent from response and event export |
| Security controls should fail closed at the earliest authoritative boundary | Apply route policy before WAF scoring and upstream network I/O | Wardnet gateway handler | upstream hit counter remains zero for rejected inputs |
| A lexical prefilter must not replace authoritative key validation | Accept only the expected credential class, then delegate existence/revocation/budget/scope to LiteLLM | ADR-0011 | valid-shaped test proves forwarding, not local authentication |
| Streaming LLM responses should not require whole-body buffering | Construct the downstream Axum body from the upstream byte stream | Wardnet proxy transport | SSE content type and rate-limit metadata round trip |

## Security interpretation

The `sk-` prefix is a **credential-class discriminator**, not proof of identity. This design prevents a known wrong class, such as a phone-shaped value, from entering LiteLLM's authentication path. It intentionally does not make a local key database, guess whether a virtual key is active, or duplicate LiteLLM's budget and scope semantics.

The guard also does not close Wardnet's complete outbound destination-policy obligation. Route upstream validation, DNS resolution, connection-time peer verification, redirect policy, and network egress controls remain a separate defense-in-depth layer.

## APA 7 references

Internet Engineering Task Force. (2012). *The OAuth 2.0 authorization framework: Bearer token usage* (RFC 6750). https://doi.org/10.17487/RFC6750

Internet Engineering Task Force. (2022). *HTTP semantics* (RFC 9110). https://doi.org/10.17487/RFC9110

National Institute of Standards and Technology. (2022). *Secure software development framework (SSDF) version 1.1: Recommendations for mitigating the risk of software vulnerabilities* (NIST Special Publication 800-218). https://doi.org/10.6028/NIST.SP.800-218

OWASP Foundation. (2025). *OWASP application security verification standard 5.0.0*. https://owasp.org/www-project-application-security-verification-standard/
