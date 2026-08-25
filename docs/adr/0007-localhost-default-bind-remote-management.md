# ADR 0007: Localhost default bind; remote management requires token plus external TLS/identity

- Status: Accepted
- Date: 2026-08-25
- Recorded from: current `main` (`README.md` bind default and
  hardening note; `docs/architecture.md` security boundaries;
  `docs/security/threat-model.md` trust boundaries)

## Context

The management API can change routes, threat lists, and DNSBL
entries. Binding to all interfaces by default would expose that
surface on the network before TLS or identity are in place.

`127.0.0.0/8` is the IPv4 loopback block (Cotton et al., 2013,
RFC 6890, Best Current Practice; Internet Assigned Numbers
Authority, n.d.). A default listen address of `127.0.0.1:8080`
keeps the process on that block unless an operator sets `BIND_ADDR`.

Block mode must not flip the whole process into global enforcement
from one mistaken write.

## Decision

1. Default `BIND_ADDR` is **`127.0.0.1:8080`** (localhost).
2. **Remote management** requires a configured **`ADMIN_TOKEN`** (or
   `ADMIN_TOKENS` / credential-registry equivalent) **and** external
   TLS plus identity controls in front of the process. This binary
   does not terminate public TLS or SSO by itself.
3. **Block mode is route-scoped.** A route's `mode` applies to that
   route's path prefix only.
4. Public clients enter through `/gateway/{path}`. Management writes
   use `X-Admin-Token` and remain upserts.

## Consequences

- `cargo run` without extra config is a local lab listener, not an
  internet-facing deployment.
- Operators who bind to a non-loopback address must supply TLS,
  identity-aware access, upstream allowlists, and rollback procedures
  before production traffic (`README.md` completion baseline).
- Unauthorized management writes remain the primary control-plane
  threat; token gates and audit logs are the current control, not a
  substitute for SSO or mTLS (`docs/security/threat-model.md`).
- RFC 6890 is a Best Current Practice for special-purpose address
  registries; it is not a WAF protocol.

## References

Cotton, M., Vegoda, L., Bonica, R., & Haberman, B. (2013).
*Special-purpose IP address registries* (RFC 6890). RFC Editor.
https://doi.org/10.17487/RFC6890

*(Best Current Practice. Documents `127.0.0.0/8` as Loopback.
Live-checked 2026-08-25 via https://www.rfc-editor.org/info/rfc6890.)*

Internet Assigned Numbers Authority. (n.d.). *IPv4 special-purpose
address space*.
https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml

*(Live-checked 2026-08-25: `127.0.0.0/8` named Loopback.)*
