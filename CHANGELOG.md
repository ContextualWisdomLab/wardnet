# Changelog

All notable changes to Wardnet are documented in this file.

## [Unreleased]

### Added

- Dedicated `litellm-virtual-key-proxy` Rust binary for deployment in front of an OpenAI-compatible LiteLLM gateway.
- Versioned JSON runtime-configuration registry bootstrapped with an exact `--config <path>` contract.
- Stable non-secret authentication rejection codes and RFC 6750 challenges.
- Fixed-origin HTTPS configuration, no-system-proxy/no-redirect transport, explicit method policy, and bounded request bodies.
- Approved request/response header projection for LLM APIs.
- Streaming upstream response relay for server-sent events and other long-running LLM responses, with a controlled multi-chunk regression proving the first chunk is forwarded before upstream completion.
- Secret-free structured authentication and transport events.
- Health endpoint exposing credential policy, configuration version, fixed-upstream policy, and body-limit state without revealing the configured hostname or performing a billable model call.
- Stable property tests and a coverage-guided libFuzzer target for the untrusted Authorization grammar.
- Security, ADR, operational, standards, and research-traceability documentation for the LiteLLM credential-class boundary.

### Security

- Reject telephone-shaped, missing, duplicate, wrong-scheme, malformed, non-ASCII, excessive-whitespace, and oversized credentials before LiteLLM upstream I/O.
- Bound the complete Authorization value before UTF-8 conversion, delimiter lookup, or whitespace scanning.
- Prevent rejected credentials and masked fragments from entering response bodies or structured proxy events.
- Strip cookies, trace baggage, forwarding-chain headers, proxy credentials, host routing, transfer framing, caller-controlled LiteLLM extensions, and arbitrary caller metadata at the LLM proxy boundary.
- Reject upstream URLs containing credentials, path prefixes, queries, or fragments; require HTTPS except loopback tests; disable ambient system proxies and redirect following.
- Convert upstream redirects to a local cache-safe 502 without returning or following the redirect target.
- Reject CONNECT, TRACE, and extension methods before upstream I/O.
