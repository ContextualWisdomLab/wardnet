# LiteLLM virtual-key ingress: standards and research traceability

## Engineering claim

A dedicated Rust reverse proxy rejects missing, duplicate, non-Bearer, and clearly non-LiteLLM credentials before upstream I/O while preserving LiteLLM as the authoritative authentication and authorization system.

## Standards traceability

| External requirement | Product decision | Implementation evidence | Test evidence |
|---|---|---|---|
| OAuth 2.0 bearer tokens are carried in the `Authorization` header using the `Bearer` scheme | Require exactly one Bearer header; emit an RFC 6750 challenge on failure | `src/litellm_credential.rs`, `src/credential_guard.rs` | unit, property, fuzz, and loopback integration tests |
| An intermediary must remove or consume connection-specific metadata rather than blindly forwarding it | Use explicit end-to-end request and response header allowlists | `forward_request_headers`, `copy_response_headers` | upstream capture verifies cookie and baggage stripping while preserving required metadata |
| Authentication failures must not disclose credentials | Emit stable reason codes only; never include a submitted value or masked fragment in JSON, structured events, or challenges | `CredentialRejection`, `rejection_response`, `emit_auth_rejection` | telephone-shaped synthetic canary is absent from the response; upstream hit count stays zero |
| Security controls should fail closed before crossing a trust boundary | Apply the credential-class guard before target construction and upstream transport | `src/litellm_guard_proxy.rs` | missing, duplicate, wrong-scheme, oversized, and telephone-shaped values never reach the loopback upstream |
| A lexical prefilter must not replace authoritative key validation | Accept only the expected credential class, then delegate existence, revocation, budget, team, and scope to LiteLLM | ADR-0011 | valid-shaped input is forwarded rather than locally authenticated |
| Runtime settings must be retrieved through a registry contract | Bootstrap a versioned JSON KV document into an immutable process-local registry; reject unknown keys and wrong types | `src/runtime_config.rs`, `ProxyConfig::from_registry` | registry and exact CLI contract tests |
| A fixed-upstream credential boundary must not use an ambient system proxy or follow an unvalidated redirect | Disable system proxies and redirects; reject upstream 3xx responses locally | `ProxyState::new`, `proxy_request` | redirect regression returns 502 without forwarding `Location` |
| Untrusted method tunnelling must be constrained | Permit the OpenAI-compatible REST method set and reject `CONNECT`, `TRACE`, and extensions | `method_allowed`, `method_not_allowed` | TRACE regression returns 405 with no upstream hit |
| Streaming LLM responses should not require whole-body buffering | Construct the downstream Axum body from the upstream byte stream | `src/litellm_guard_proxy.rs` | controlled two-chunk SSE test receives headers and the first chunk before the final chunk is released, then verifies normal completion |
| Changed untrusted-input grammars require variance-reducing tests | Keep stable property tests and a libFuzzer target on the same pure parser | `tests/litellm_credential_properties.rs`, `fuzz/fuzz_targets/fuzz_litellm_credential.rs` | primary CI property suite and bounded PR/nightly fuzz matrix |

## Research-to-design traceability

| Research source | Evidence summary | Implementation influence |
|---|---|---|
| Gao et al. (2026) | In a dataset of 444 LLM-integrated iOS applications, 282 exposed exploitable LLM credentials; unauthenticated backend proxy access was one of the recurring leakage patterns. The paper argues for platform-level enforcement in addition to developer guidance. | Wardnet rejects absent or clearly wrong credential classes at the shared proxy boundary instead of relying solely on each caller. The proxy does not store the key database; authoritative virtual-key checks remain in LiteLLM. |
| Meli et al. (2019) | A large-scale longitudinal GitHub study found secret leakage pervasive across more than 100,000 repositories and continuing through new commits. | No usable virtual key appears in source-controlled configuration examples. Rejected values are not reflected or logged, and runtime settings are read from a registry document rather than compiled constants or per-value environment access. |
| Crosby and Wallach (2003) | Attacker-controlled inputs can exploit worst-case algorithmic behavior to cause low-bandwidth denial of service, including in proxy and IDS software. | The complete `Authorization` header is length-checked before UTF-8 conversion or delimiter scans; separator and token lengths are bounded; parsing is linear; property and coverage-guided fuzz tests exercise arbitrary bytes, duplicate values, whitespace, boundary lengths, and padding positions. |

No research PDF is committed in this PR because redistribution permission was not verified uniformly across the sources. Publisher and author-hosted pages are linked, and each source's concrete design impact is recorded here and in ADR-0011.

## Security interpretation

The `sk-` prefix is a **credential-class discriminator**, not proof of identity. This design prevents a known wrong class, such as a telephone-shaped value, from entering LiteLLM's authentication path. It intentionally does not make a local key database, guess whether a virtual key is active, or duplicate LiteLLM's team, model, budget, and scope semantics.

The upstream origin is registry-owned rather than caller-owned. The first release requires HTTPS except loopback tests, rejects URL credentials, paths, queries, and fragments, disables system proxies, and locally rejects redirects. Resolved-address policy, DNS rebinding resistance, and connection-time peer verification remain additional defense-in-depth work for deployments whose configuration registry is not already authoritative.

## APA 7 references

Crosby, S. A., & Wallach, D. S. (2003). Denial of service via algorithmic complexity attacks. In *Proceedings of the 12th USENIX Security Symposium* (pp. 29–44). USENIX Association. https://www.usenix.org/conference/12th-usenix-security-symposium/denial-service-algorithmic-complexity-attacks

Gao, P., Wang, L., Zhang, Y., & Yang, F. (2026). *Mind your key: An empirical study of LLM API credential leakage in iOS apps* [Preprint]. arXiv. https://doi.org/10.48550/arXiv.2606.12212

Internet Engineering Task Force. (2012). *The OAuth 2.0 authorization framework: Bearer token usage* (RFC 6750). https://doi.org/10.17487/RFC6750

Internet Engineering Task Force. (2022). *HTTP semantics* (RFC 9110). https://doi.org/10.17487/RFC9110

Meli, M., McNiece, M. R., & Reaves, B. (2019). How bad can it Git? Characterizing secret leakage in public GitHub repositories. In *Proceedings of the Network and Distributed System Security Symposium*. Internet Society. https://doi.org/10.14722/ndss.2019.23418

National Institute of Standards and Technology. (2022). *Secure software development framework (SSDF) version 1.1: Recommendations for mitigating the risk of software vulnerabilities* (NIST Special Publication 800-218). https://doi.org/10.6028/NIST.SP.800-218

OWASP Foundation. (2025). *OWASP application security verification standard 5.0.0*. https://owasp.org/www-project/application-security-verification-standard/
