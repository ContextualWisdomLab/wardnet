# ADR-0011: Guard LiteLLM virtual-key credentials at Wardnet ingress

- Status: Proposed
- Date: 2026-08-20
- Decision owner: Wardnet gateway security boundary

## Context

The development LLM gateway emitted high-severity `llm_exceptions` alerts because a phone-number-shaped credential reached LiteLLM where a virtual key beginning with `sk-` was required. Treating the exception as an ordinary upstream failure creates avoidable alert noise, spends upstream capacity, and allows the wrong credential class to cross the edge boundary.

Wardnet is the ContextualWisdomLab WAF/IDS/software-load-balancer/APIM and already owns route-level request enforcement. EgressWeave protects Python outbound calls and therefore is not the correct owner for an inbound reverse-proxy credential gate. Contextual Orchestrator owns model routing; LiteLLM owns virtual-key authentication, revocation, team, budget, and scope.

## Decision

Add an optional `authorization_policy` to each Wardnet route:

- `none` preserves existing behavior.
- `litellm_virtual_key` requires exactly one RFC 6750 Bearer credential whose bounded lexical shape starts with `sk-`.

The guard:

1. runs after cheap admission control and before WAF scoring or upstream I/O;
2. never rewrites or prepends a prefix to a supplied credential;
3. records only stable non-secret reason codes;
4. returns `401`, an RFC 6750 `WWW-Authenticate` challenge, and `Cache-Control: no-store`;
5. forwards the accepted `Authorization` header only to the configured upstream;
6. strips cookies, forwarding-chain, proxy-authentication, host, and hop-by-hop headers;
7. streams the upstream response and preserves only approved streaming, correlation, retry, and rate-limit headers.

LiteLLM remains authoritative. Passing this shape gate does not prove that a key exists or is entitled to use a model.

## Consequences

### Positive

- Phone numbers, account identifiers, and other obvious wrong credential classes fail before LiteLLM.
- The edge response is deterministic and does not disclose the rejected value.
- Existing non-LLM routes remain compatible through the default `none` policy.
- The implementation is a bounded, allocation-minimal Rust hot path and avoids buffering LLM streaming responses.
- Security events distinguish credential-boundary failures from model/provider exceptions.

### Negative

- Prefix validation cannot detect a revoked, unknown, over-budget, or under-scoped `sk-` value.
- A misconfigured administrator can still point a route at an inappropriate upstream; the complete destination-policy/SSRF control remains tracked separately.
- Clients using a non-LiteLLM key convention must use another route policy rather than weakening this one.

## Rejected alternatives

### Automatically prepend `sk-`

Rejected because it converts malformed input into a different secret, hides the true caller defect, and could create ambiguous identity.

### Implement the guard in every LLM client

Rejected because clients are heterogeneous and the exposed gateway requires one fail-closed ingress control in addition to client-side validation.

### Move the check to EgressWeave

Rejected because EgressWeave is an outbound Python SSRF/DNS-rebinding library, not the inbound high-throughput APIM authority.

### Replace Wardnet with a new proxy

Rejected for this bounded change. Wardnet already has the correct product responsibility and a Rust data plane. A future Pingora transport can reuse the same policy contract without changing route semantics.
