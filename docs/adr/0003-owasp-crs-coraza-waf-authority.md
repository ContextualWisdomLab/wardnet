# ADR 0003: OWASP CRS / Coraza as WAF authority

- Status: Accepted
- Date: 2026-08-25
- Recorded from: current `main` (`README.md` production-coverage note;
  `docs/architecture.md` near-term WAF integration)

## Context

The gateway scores requests from local threat indicators and DNSBL
entries. That baseline is not a replacement for a maintained WAF rule
set. Inventing an in-house rule language would duplicate work the
OWASP Core Rule Set already does for generic attack detection
(OWASP Foundation / CRS Project, n.d.).

OWASP Coraza is an open-source WAF engine documented as compatible
with OWASP CRS (OWASP Coraza, n.d.). Current `main` already accepts
Coraza/CRS **audit** documents; it does not embed Coraza in-process.

## Decision

1. **OWASP CRS remains the WAF rule authority.** Do not replace CRS
   with a hand-rolled rule engine or claim that Wardnet's local
   signatures are equivalent to CRS.
2. Accept admin-authenticated Coraza / OWASP CRS **audit JSON/NDJSON**
   at `POST /api/waf/coraza/audit`. Interrupted transactions and CRS
   rule messages become `SecurityEvent` rows. Block-grade hits may seed
   DNSBL and `client_ip` / path threat indicators so later gateway
   decisions can enforce matching clients.
3. Run Coraza **outside** this process for now. **In-process Coraza
   embedding is a follow-up**, not an accepted replacement of CRS and
   not an accepted replacement of the audit ingest path.
4. Current `main` may still apply bounded built-in signatures and a
   lightweight anomaly heuristic during gateway scoring. Those are
   supplemental local heuristics for first-pass triage and blocking;
   they are **not** presented as WAF authority, CRS parity, or a
   substitute for Coraza-backed enforcement.

Related accepted ingest on the same `main` (IDS, not WAF authority):
admin-authenticated Suricata EVE JSON/NDJSON at
`POST /api/ids/suricata/eve` (Eve JSON output, n.d.). Full route
correlation and live EVE tailing remain follow-ups.

## Consequences

- Operators can attach an external Coraza/CRS deployment and still use
  this gateway for scoring, events, and route-scoped block mode.
- CRS versioning and rule quality stay with the CRS project (latest
  line observed 2026-08-25: 4.29.0 on https://coreruleset.org/).
- Embedding Coraza later must still consume CRS; it must not become a
  pretext for a parallel hand-written rule pack.

## References

OWASP Coraza. (n.d.). *Documentation*. https://coraza.io/docs/

OWASP Coraza. (n.d.). *OWASP Coraza WAF*. https://coraza.io/

OWASP Foundation / CRS Project. (n.d.). *OWASP Core Rule Set*.
https://coreruleset.org/

Eve JSON output. (n.d.). In *Suricata documentation*.
https://docs.suricata.io/en/latest/output/eve/eve-json-output.html
