# Changelog

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

### Security

- Fail closed before readiness when `BIND_ADDR` is not loopback-only and no write-capable admin principal is configured (`ADMIN_TOKEN`, `ADMIN_TOKENS`, or `WAF_IDS_CREDENTIALS_PATH`). Loopback development may still start without a token and reports `auth_mode=development` on `/healthz`.
- A blank `WAF_IDS_STATE_PATH` is treated as in-memory state instead of becoming ready and then failing to replace an empty path.
- Fail-closed destination policy on every outbound `http`/`https` call (gateway upstream, threat-intel fetch, Clearfolio, SOC LLM). Loopback/private/link-local/metadata destinations are denied unless `DESTINATION_ALLOWLIST` (or loopback development) permits them; `DESTINATION_DENYLIST` wins. Clients ignore ambient HTTP proxy variables and do not follow redirects.
- Management writes now distinguish `401` (unauthenticated) from `403` (authenticated, not permitted to write) without naming the expected role.
- Presented admin secrets are compared in constant time. Duplicate, blank, and unknown `ADMIN_TOKENS` roles fail startup.

### Documentation

- Product/technical gap baseline at `docs/product-technical-gap-baseline.md` (open PRs/Issues inventory, operator-perceptible gaps, Figma file IDs, UI-UX areas).
- File://-openable admin-console scene and edge-case inventory at `docs/ui-ux/storybook-scene-inventory.md`.
- Figma file IDs recorded in `docs/adr/0001-figma-and-design-system.md` and `docs/architecture.md`.
