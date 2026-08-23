# Changelog

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

### Security

- Live `/gateway` transactions consult a Coraza sidecar when `CORAZA_WAF_URL` is set. The sidecar response is parsed with the existing Coraza audit adapter (OWASP CRS authority, not a hand-rolled engine). Sidecar outage is fail-closed when `PROVEN_ENGINE_FAIL_CLOSED` is true. `GET /api/waf/engine-status` and `/healthz.proven_engine` report the mode.
- Fail-closed destination policy on every outbound `http`/`https` call, including the Coraza sidecar URL (gateway upstream, threat-intel fetch, Clearfolio, SOC LLM). Private/loopback/metadata classes are denied unless `DESTINATION_ALLOWLIST` (or loopback development) permits them; `DESTINATION_DENYLIST` wins. Clients ignore ambient HTTP proxies and do not follow redirects. CIDR allowlist matches apply per resolved address; CIDR entries authorize non-default ports; IPv6 site-local (`fec0::/10`) is denied; invalid CIDR prefixes fail startup; `/healthz.destination_mode` reports the policy class. Blocking DNS runs on `spawn_blocking` with a 2s timeout. Persistence and destination-list validation complete before the readiness line is printed.
