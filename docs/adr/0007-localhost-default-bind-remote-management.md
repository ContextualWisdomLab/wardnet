# ADR 0007: Localhost default bind; remote management requires write-capable auth plus external TLS/identity

- Status: Accepted
- Date: 2026-08-25
- Reconciled: 2026-09-13 against protected `main@f8260f1e03836039ff9463dd99fa982e4e270c4b`
- Recorded from: `README.md` bind default and hardening note;
  `docs/architecture.md` security boundaries;
  `docs/security/threat-model.md` trust boundaries; protected #155

## Context

The management API can change routes, threat lists, and DNSBL
entries. Binding to all interfaces by default would expose that
surface on the network before TLS or identity are in place.

`127.0.0.0/8` is the IPv4 loopback block (Cotton et al., 2013,
RFC 6890, Best Current Practice; Internet Assigned Numbers
Authority, n.d.). A default listen address of `127.0.0.1:8080`
keeps the process on that block unless an operator sets `BIND_ADDR`.

A remote listener also needs a credential that can actually authorize
management writes. Merely configuring a credential registry is not
sufficient if it is empty, header-ambiguous, or contains only read-only
principals. Block mode must not flip the whole process into global
enforcement from one mistaken write.

## Decision

1. Default `BIND_ADDR` is **`127.0.0.1:8080`** (localhost).
2. A non-loopback bind **fails closed before serving** unless Wardnet
   has at least one valid, presentable, write-capable administrator
   credential from `ADMIN_TOKEN`, `ADMIN_TOKENS`, or the supported
   credential-registry equivalent. Empty, unusable, ambiguous, or
   read-only-only credential configurations do not satisfy this gate.
3. Remote management additionally requires external TLS and
   identity-aware access controls in front of the process. Wardnet does
   not treat its bearer credential as a substitute for public TLS, SSO,
   mTLS, upstream allowlists, or operator identity governance.
4. **Block mode is route-scoped.** A route's `mode` applies to that
   route's path prefix only.
5. Public clients enter through `/gateway/{path}`. Management writes
   use the supported administrator-authentication contract and remain
   upserts; authentication and authorization semantics must remain
   consistent across health/management paths and smoke/runtime evidence.

## Consequences

- `cargo run` without extra config is a local lab listener, not an
  internet-facing deployment.
- Protected #155 removed the predecessor fail-open state: current
  protected `main` rejects public bind when no usable write-capable
  administrator can be presented and rejects unusable or
  header-ambiguous bootstrap credentials. This is implementation
  evidence for the bind/auth gate, not evidence that TLS or enterprise
  identity is provided by Wardnet.
- Operators who bind to a non-loopback address still must supply TLS,
  identity-aware access, upstream allowlists, secret lifecycle, and
  rollback procedures before production traffic (`README.md` completion
  baseline).
- Unauthorized management writes remain a primary control-plane threat;
  credential gates, RBAC, and audit logs are controls, not substitutes
  for SSO or mTLS (`docs/security/threat-model.md`).
- A read-only principal is intentionally insufficient to make a public
  management listener release-ready because it cannot authorize the
  control-plane recovery/change path that the listener exposes.
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
