# Phishing.Database SSRF trust boundary

## Decision

Wardnet does not accept a Phishing.Database feed URL, hostname, or host-relaxation flag from the import request. Production code selects the domain and IP feeds from server-owned constants, validates that the selected URL is HTTP(S) and belongs to the sanctioned upstream host set, and uses a no-redirect HTTP client. Loopback URLs exist only behind `cfg(test)` so hostile integration tests can exercise the fetch path without adding production mirror authority.

The boundary is split deliberately:

- `validate_http_url` establishes the narrow URL syntax/scheme precondition used by the feed importer.
- `validate_phishing_database_source_url` adds the product-specific authority check: only the server-selected Phishing.Database source hosts are valid in production.
- `AppState::phishing_database_domain_url` and `AppState::phishing_database_ip_url` return built-in production URLs; runtime overrides are test-only.
- `feed_http` disables redirects, preventing an initially allowed origin from redirecting the fetch to a different network destination.
- EgressWeave remains the canonical reusable outbound URL/address/DNS/peer/redirect/proxy/TLS/resource authorization owner. This Wardnet check is the importer-specific source-selection boundary, not a replacement for executable transport authorization.

This is intentionally stricter than validating an arbitrary request-supplied URL. The business flow knows the authoritative feed in advance, so the safest representation is a server-owned identifier/constant rather than a client-controlled network location.

## Threat model and evidence

The protected baseline allowed an authenticated caller to submit `domain_url`, `ip_url`, and `allow_non_default_hosts`. A hostile baseline test used those fields to point the server at a loopback feed and observed that the loopback endpoint was fetched. That is the relevant SSRF condition: the server performed a network request to a destination selected by upstream request data.

Jabiyev, Mirzaei, Kharraz, and Kirda (2021) identify this user-input-to-server-request relationship as a fundamental condition for SSRF. Their study of more than 60 disclosed SSRF vulnerability reports found that application-level defenses were frequently incomplete or retained important security/functionality limitations. The direct implication for this importer is to remove destination authority from request data instead of depending on a caller-controlled URL plus an escape hatch.

OWASP's current SSRF prevention guidance reaches the same design conclusion for flows with known trusted destinations: use an allowlist, avoid accepting complete URLs from users where possible, disable redirect following, and combine application-layer validation with network-layer controls. CWE-918 likewise characterizes SSRF as insufficient assurance that a server-side request is sent to the expected destination.

The production repair therefore removes request-selected feed URLs and the `allow_non_default_hosts` switch rather than attempting to make that switch safer. The hostile regression asserts the security property directly: request-selected loopback input cannot cause a loopback fetch. It does not require one incidental HTTP status code, because an upstream availability failure can legitimately change the response status without reopening the SSRF path.

## Ownership and non-goals

Wardnet owns the Phishing.Database import contract, its product-specific source authority, the resulting threat-feed evidence, and the final SOC/security policy state. It does not own a second general egress policy engine.

This repair does not:

- copy EgressWeave DNS, IP-range, peer, proxy, redirect, TLS, or resource authorization logic;
- make a Wardnet source allowlist authoritative for unrelated outbound traffic;
- inspect or mutate quarantine runtime networking;
- permit production loopback or operator-selected mirror URLs;
- infer safety from authentication alone;
- treat successful URL parsing as destination authorization.

A future released EgressWeave contract can provide the transport-level authorization evidence independently. Wardnet's importer-specific source decision and EgressWeave's transport decision are conjunctive controls: neither authority may override the other's deny.

## Verification contract

The repair is accepted only when one exact PR head proves all of the following:

1. the protected-baseline hostile companion reaches the semantic assertion and demonstrates an actual request-selected loopback fetch;
2. the repaired request schema no longer exposes production feed URL or host-relaxation authority;
3. production feed resolution is server-owned, while loopback override remains test-only;
4. the no-redirect client and sanctioned-host validation remain present;
5. the carried hostile regression proves the request-selected loopback endpoint receives zero fetches;
6. then-live CI, fuzz, security/static-analysis, review/thread, and protected-integration evidence are reacquired for that exact head.

Predecessor success does not transfer after source, documentation, base, or merge-head movement.

## Research artifact handling

The SecLab-hosted author copy of Jabiyev et al. is linked below for verification, but it is **not** committed under `docs/papers/`. The paper carries ACM copyright language that permits personal/classroom copying while requiring permission or a fee for republication or redistribution to servers. A publicly reachable author copy is not, by itself, a repository redistribution license. Wardnet therefore records the APA reference, DOI, author-hosted link, and the evidence used for this decision without repackaging the PDF.

OWASP Cheat Sheet Series material is published under CC BY-SA 4.0, but no local copy is needed for this decision; the canonical maintained page is linked instead.

## References

Jabiyev, B., Mirzaei, O., Kharraz, A., & Kirda, E. (2021). Preventing server-side request forgery attacks. In *Proceedings of the 36th ACM/SIGAPP Symposium on Applied Computing (SAC '21)* (pp. 1626–1635). Association for Computing Machinery. https://doi.org/10.1145/3412841.3442036

Jabiyev, B., Mirzaei, O., Kharraz, A., & Kirda, E. (2021). *Preventing server-side request forgery attacks* [Author-hosted PDF]. NEU SecLab. https://seclab.nu/static/publications/sac21-prevent-ssrf.pdf

MITRE. (2026). *CWE-918: Server-side request forgery (SSRF)*. Common Weakness Enumeration. https://cwe.mitre.org/data/definitions/918.html

OWASP Foundation. (2026). *Server side request forgery prevention cheat sheet*. OWASP Cheat Sheet Series. https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
