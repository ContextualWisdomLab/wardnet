# In-path Coraza request adapter

## Decision boundary

Wardnet owns route selection, monitor/block policy, security-event production, and the decision to forward a request. It does not own OWASP CRS detection logic. When a `ProvenEngineConfig` sidecar is configured, Wardnet submits each matched live gateway request to a same-host Coraza/OWASP CRS evaluator before forwarding. The adapter is intentionally loopback-only; executable general-purpose egress authorization remains EgressWeave ownership and is not copied into Wardnet.

The request envelope contains method, effective gateway URI, body, client address when known, a bounded non-secret header allowlist, Wardnet route-policy identity, and contract identifier `coraza-live-evaluate-v1`. `Authorization`, `Cookie`, `Proxy-Authorization`, and `X-Admin-Token` are never forwarded. Raw `X-Forwarded-For` and `X-Real-IP` are also withheld until Wardnet's trusted-proxy attribution owner reaches protected truth; the sidecar receives the transport-derived `client_ip` separately. Header forwarding is capped at 32 fields / 8 KiB. If any allowlisted value cannot be represented as UTF-8 or the complete allowlisted envelope would exceed either cap, Wardnet records `engine_unavailable` and does not call the sidecar; a partial request projection is never eligible for a clean verdict. Sidecar evaluation has a 1.5 s timeout and a 1 MiB response cap.

A sidecar response is not accepted merely because it is HTTP 2xx. Wardnet requires parseable JSON evidence correlated to the exact request method and URI. A clean decision additionally requires an explicit non-interrupted transaction, a response status below 400, and an empty messages array. Coraza/CRS rule messages retain their rule text/ID as SOC evidence, but the live adapter projects enforcement authority separately: only explicit `is_interrupted=true`, HTTP 403/406 from the sidecar, or transaction response 403/406 is disruptive. A non-interrupted successful transaction with rule messages remains monitor evidence and is never promoted to a block merely because audit severity maps to a high score. Wardnet adds policy identity plus sidecar ruleset identity when supplied. An unconfigured engine and malformed, oversized, uncorrelated, timed-out, or unreachable evidence are `engine_unavailable`; a block-mode route fails closed with HTTP 503. Independent Wardnet threat/DNSBL evidence may deny a request first; Coraza is the required authorization boundary only for block-mode traffic that has not already been denied and would otherwise proceed upstream. Monitor mode records the degraded evidence and may continue, preserving route-scoped semantics.

`tests/coraza_proven_engine_adapter.rs` uses a protocol fixture, not a substitute detector. The fixture returns Coraza-shaped block/clean evidence by test URI so the test proves Wardnet forwards the hostile `User-Agent`, excludes credential-bearing headers, correlates the response, enforces block versus monitor semantics, and fails closed on unusable engine evidence. Production detection authority remains a real Coraza deployment with a pinned OWASP CRS ruleset.

## Operational acceptance

Before exposing a block-mode route through this boundary, deploy the Coraza evaluator on loopback, pin and inventory the CRS policy/ruleset, then construct `AppState` with `ProvenEngineConfig::sidecar(...)`. The current bounded slice does not add a new environment-variable or database configuration source because Runtime Configuration is owned by its separate Wardnet lane. That owner must expose the released/configured adapter without reintroducing handler-time environment reads before this becomes a packaged production default.

Treat `engine_unavailable` events as protection-loss evidence. Do not convert malformed or uncorrelated evidence to `Clean`, and do not add local request signatures to compensate for a missing Coraza engine.

## Traceability

Coraza. (n.d.). *Coraza Web Application Firewall documentation*. https://coraza.io/docs/

National Institute of Standards and Technology. (2007). *Guide to intrusion detection and prevention systems (IDPS)* (NIST Special Publication 800-94). https://doi.org/10.6028/NIST.SP.800-94

OWASP Foundation. (2025). *OWASP Core Rule Set documentation*. https://coreruleset.org/docs/

Saltzer, J. H., & Schroeder, M. D. (1975). The protection of information in computer systems. *Proceedings of the IEEE, 63*(9), 1278–1308. https://doi.org/10.1109/PROC.1975.9939

These references ground the use of a proven WAF/ruleset authority and fail-safe treatment of unavailable or unverifiable decisions. They are rationale, not evidence that a specific Coraza/CRS build has been deployed or released. No paper PDF is added in this lane because redistribution permission for the exact retrieved versions was not independently established.
