# ADR-0011: Guard LiteLLM virtual-key credentials at Wardnet ingress

- Status: Proposed
- Date: 2026-08-20
- Decision owner: Wardnet gateway security boundary

## Context

The development LLM gateway emitted high-severity `llm_exceptions` alerts because a phone-number-shaped credential reached LiteLLM where a virtual key beginning with `sk-` was required. Treating this as an ordinary upstream model exception creates avoidable alert noise, consumes upstream capacity, and lets the wrong credential class cross the edge boundary.

Wardnet is the ContextualWisdomLab WAF/IDS/software-load-balancer/APIM and therefore owns this inbound proxy control. EgressWeave protects Python outbound calls and is not the correct owner. Contextual Orchestrator owns model routing; LiteLLM owns virtual-key authentication, revocation, team, budget, model scope, and provider selection.

The existing general Wardnet gateway remains useful for mixed routes, but its current request/response transport is not an ideal place for a narrowly scoped LLM credential boundary because unrelated routes must remain backward compatible. The organization also requires modules to operate both independently and as ecosystem components.

## Decision

Add a dedicated Rust binary inside Wardnet:

```text
litellm-virtual-key-proxy
```

The binary has one fixed, operator-configured LiteLLM upstream and applies the `litellm_virtual_key` credential policy to every proxied request. It is deployable as a sidecar, internal edge service, or separate container in front of `https://llm-gateway-dev.hyosungitx.com`.

The guard:

1. requires exactly one RFC 6750 Bearer credential;
2. performs one bounded scan of at most 512 credential bytes;
3. requires the lexical LiteLLM virtual-key class beginning `sk-`;
4. runs before upstream network I/O;
5. never rewrites or prepends a prefix to a supplied credential;
6. emits only stable non-secret reason codes;
7. returns `401`, an RFC 6750 `WWW-Authenticate` challenge, and `Cache-Control: no-store`;
8. forwards the accepted `Authorization` header only to the fixed upstream;
9. strips cookies, forwarding-chain, proxy-authentication, host, transfer-framing, and arbitrary headers;
10. disables upstream redirects and requires HTTPS except loopback HTTP used by tests;
11. streams upstream responses and preserves only approved streaming, correlation, retry, authentication, and rate-limit headers.

LiteLLM remains authoritative. Passing this shape gate does not prove that a key exists or is entitled to use a model.

## Consequences

### Positive

- Phone numbers, account identifiers, and other obvious wrong credential classes fail before LiteLLM.
- The edge response and structured rejection event do not disclose the rejected value or a masked fragment.
- Existing Wardnet routes are unchanged.
- The binary is independently deployable and can later be embedded behind the general Wardnet control plane.
- The bounded Rust hot path is allocation-minimal, and LLM server-sent events are relayed without whole-response buffering.
- Fixed upstream configuration and no-redirect behavior avoid turning a caller-controlled value into an outbound destination.

### Negative

- Prefix validation cannot detect a revoked, unknown, over-budget, or under-scoped `sk-` value.
- The initial binary does not persist rejection events into Wardnet's main SOC state; it emits secret-free structured events for the deployment log pipeline.
- Broader production egress controls such as resolved-address policy and connection-time peer verification remain defense-in-depth work outside this narrow alert fix.
- Deployments now run an additional binary unless the module is incorporated into the primary data plane later.

## Rejected alternatives

### Automatically prepend `sk-`

Rejected because it converts malformed input into a different secret, hides the caller defect, and creates ambiguous identity.

### Implement the guard only in each LLM client

Rejected because callers are heterogeneous. Client-side validation remains useful, but the exposed gateway requires one fail-closed ingress boundary.

### Move the check to EgressWeave

Rejected because EgressWeave is an outbound Python SSRF/DNS-rebinding library, not an inbound high-throughput APIM authority.

### Modify every existing Wardnet route

Rejected for the first slice because it would change a generic proxy contract and mix unrelated route compatibility concerns into the alert fix.

### Replace Wardnet with another proxy product

Rejected. Wardnet already owns the correct responsibility and is Rust-first. A future Pingora transport can reuse the same credential contract without moving the product boundary.
