# ADR-0011: Guard LiteLLM virtual-key credentials at Wardnet ingress

- Status: Proposed
- Date: 2026-08-20
- Decision owner: Wardnet gateway security boundary

## Context

The development LLM gateway emitted high-severity `llm_exceptions` alerts because a phone-number-shaped credential reached LiteLLM where a virtual key beginning with `sk-` was required. Treating this as an ordinary upstream model exception creates avoidable alert noise, consumes upstream capacity, and lets the wrong credential class cross the edge boundary.

Wardnet is the ContextualWisdomLab WAF/IDS/software-load-balancer/APIM and therefore owns this inbound proxy control. EgressWeave protects Python outbound calls and is not the correct owner. Contextual Orchestrator owns model routing; LiteLLM owns virtual-key authentication, revocation, team, budget, model scope, and provider selection.

The existing general Wardnet gateway remains useful for mixed routes, but its current request/response transport is not the ideal first location for a narrowly scoped LLM credential boundary because unrelated routes must remain backward compatible. The organization also requires modules to operate both independently and as ecosystem components.

## Research evidence and design impact

| Evidence | Relevant finding | Design impact |
|---|---|---|
| Gao, Wang, Zhang, and Yang (2026) | Their empirical study of 444 LLM-integrated iOS applications found exploitable LLM credentials in 282 applications and identified unauthenticated backend proxy access as one recurring leakage pattern. The authors call for platform-level enforcement in addition to developer guidance. | Put a fail-closed credential boundary at the proxy, require authentication material before upstream I/O, keep the LLM provider gateway authoritative, and avoid relying on every client to choose the correct credential class. |
| Meli, McNiece, and Reaves (2019) | Their large-scale longitudinal study found secret leakage to be pervasive in public source repositories and persistent in new commits. | Do not embed or echo credentials; load operational configuration through a registry document; keep submitted tokens out of logs, traces, support bundles, responses, fixtures, and source-controlled deployment examples. |
| Crosby and Wallach (2003) | They demonstrated that attacker-controlled inputs can exploit unfavorable algorithmic behavior to create low-bandwidth denial of service, including against proxies and intrusion-detection software. | Bound the complete `Authorization` value before conversion or delimiter scans, cap separator and token lengths, use a linear bounded parser, and maintain both stable property tests and coverage-guided fuzzing for the untrusted-input grammar. |

The implementation cites and links publisher or author-hosted sources. It does not copy paper PDFs into the repository because redistribution permission was not verified for every source. The USENIX paper explicitly permits noncommercial reproduction of the complete proceedings for educational or research purposes, but this product repository keeps a consistent link-and-summary policy rather than mixing redistribution regimes.

## Decision

Add a dedicated Rust binary inside Wardnet:

```text
litellm-virtual-key-proxy
```

The binary has one fixed, registry-configured LiteLLM origin and applies the `litellm_virtual_key` credential policy to every proxied request. It is deployable as a sidecar, internal edge service, or separate container in front of `https://llm-gateway-dev.hyosungitx.com`.

The guard and transport:

1. require exactly one RFC 6750 Bearer credential;
2. reject an oversized `Authorization` value before UTF-8 conversion, delimiter lookup, or whitespace scans;
3. permit at most eight ASCII separator spaces and a token of at most 512 bytes;
4. require the lexical LiteLLM virtual-key class beginning `sk-`;
5. run before upstream network I/O;
6. never rewrite or prepend a prefix to a supplied credential;
7. emit only stable non-secret reason codes;
8. return `401`, an RFC 6750 `WWW-Authenticate` challenge, and cache-prevention headers;
9. forward the accepted `Authorization` header only to the fixed upstream;
10. strip cookies, forwarding-chain, proxy-authentication, host, transfer-framing, trace baggage, and arbitrary request headers;
11. read versioned operational values from a process-local runtime registry bootstrapped with `--config <path>`, not raw per-value environment lookups;
12. require an HTTPS origin without credentials, path prefix, query, or fragment, except loopback HTTP used by tests;
13. disable system-proxy discovery and redirect following, and convert upstream redirects to a local `502`;
14. reject `CONNECT`, `TRACE`, and extension methods before upstream I/O;
15. stream upstream responses and preserve only approved streaming, correlation, retry, authentication, and rate-limit headers;
16. maintain synchronized unit, integration, property, and libFuzzer coverage for the credential parser.

LiteLLM remains authoritative. Passing this shape gate does not prove that a key exists or is entitled to use a model.

## Consequences

### Positive

- Phone numbers, account identifiers, and other obvious wrong credential classes fail before LiteLLM.
- The edge response and structured rejection event do not disclose the rejected value or a masked fragment.
- Existing Wardnet routes are unchanged.
- The binary is independently deployable and can later be embedded behind the general Wardnet control plane.
- The bounded Rust hot path has deterministic linear work over a small maximum input, and LLM server-sent events are relayed without whole-response buffering.
- Fixed-origin configuration, no system proxy, and local rejection of redirects prevent the accepted credential from being carried to a caller-selected or redirected destination.
- A versioned registry document makes the operational contract reviewable, type-checked, and portable to a durable KV materializer.

### Negative

- Prefix validation cannot detect a revoked, unknown, over-budget, or under-scoped `sk-` value.
- The initial binary does not persist rejection events into Wardnet's main SOC state; it emits secret-free structured events for the deployment log pipeline.
- Broader production egress controls such as resolved-address policy, DNS rebinding resistance, and connection-time peer verification remain defense-in-depth work outside this narrow alert fix.
- Deployments now run an additional binary unless the module is incorporated into the primary data plane later.
- The strict header allowlist may require explicit review before supporting a new LiteLLM request extension.

## Rejected alternatives

### Automatically prepend `sk-`

Rejected because it converts malformed input into a different secret, hides the caller defect, and creates ambiguous identity.

### Implement the guard only in each LLM client

Rejected because callers are heterogeneous. Client-side validation remains useful, but the exposed gateway requires one fail-closed ingress boundary.

### Move the check to EgressWeave

Rejected because EgressWeave is an outbound Python SSRF/DNS-rebinding library, not an inbound high-throughput APIM authority.

### Modify every existing Wardnet route

Rejected for the first slice because it would change a generic proxy contract and mix unrelated route compatibility concerns into the alert fix.

### Store the actual LiteLLM virtual keys in Wardnet

Rejected because it duplicates LiteLLM's authentication, revocation, scope, team, and budget authority and would enlarge Wardnet's secret-bearing state.

### Replace Wardnet with another proxy product

Rejected. Wardnet already owns the correct responsibility and is Rust-first. A future Pingora transport can reuse the same credential contract without moving the product boundary.

## References

Crosby, S. A., & Wallach, D. S. (2003). Denial of service via algorithmic complexity attacks. In *Proceedings of the 12th USENIX Security Symposium* (pp. 29–44). USENIX Association. https://www.usenix.org/conference/12th-usenix-security-symposium/denial-service-algorithmic-complexity-attacks

Gao, P., Wang, L., Zhang, Y., & Yang, F. (2026). *Mind your key: An empirical study of LLM API credential leakage in iOS apps* [Preprint]. arXiv. https://doi.org/10.48550/arXiv.2606.12212

Meli, M., McNiece, M. R., & Reaves, B. (2019). How bad can it Git? Characterizing secret leakage in public GitHub repositories. In *Proceedings of the Network and Distributed System Security Symposium*. Internet Society. https://doi.org/10.14722/ndss.2019.23418
