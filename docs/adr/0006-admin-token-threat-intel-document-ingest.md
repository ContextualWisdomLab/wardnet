# ADR 0006: Admin-token threat-intel document ingest

- Status: Accepted
- Date: 2026-08-25
- Recorded from: current `main` (`docs/architecture.md` threat
  intelligence paragraph; admin console copy for the ingest routes)

## Context

Gateway scoring needs threat indicators and DNSBL entries. Operators
already hold documents from STIX/TAXII, MISP, and OpenCTI. Those
documents are untrusted until validated. Live pull jobs against a
MISP REST API or an OpenCTI GraphQL endpoint are a different
operational surface (credentials, scheduling, pagination) and are
**not** accepted on current `main`.

STIX 2.1 is an OASIS Standard for exchanging cyber threat
intelligence objects (Jordan et al., 2021a). TAXII 2.1 is the OASIS
Standard for transporting STIX over HTTP collections (Jordan &
Varner, 2021). MISP is an open threat-intelligence sharing platform
and associated open standards (MISP Project, n.d.; MISP Standard,
n.d.). OpenCTI documents an open CTI platform with official
operator documentation (OpenCTI, n.d.).

## Decision

1. Ingest **operator-posted documents** on admin-authenticated routes:
   - `POST /api/threat-intel/stix` — STIX 2.x indicator or bundle JSON
   - `POST /api/threat-intel/misp` — MISP Event / attribute JSON
     (`to_ids=false` attributes skipped)
   - `POST /api/threat-intel/taxii/poll` — TAXII 2.1 collection
     objects URL (or API root + collection id); optional Basic/Bearer;
     normalize to STIX then upsert
   - `POST /api/threat-intel/opencti` — OpenCTI observable / indicator
     export JSON
2. Map supported IP, domain, URL, and hash material into
   `ThreatIndicator` and `DnsblEntry` rows and update feed freshness.
3. **Live MISP REST pull** and **live OpenCTI GraphQL pull** remain
   follow-ups. They are not accepted replacements for document ingest.
4. Never write TAXII or admin credentials into audit-log payloads.

## Consequences

- An operator (or an external poller they control) can push reviewed
  intelligence without this process holding a standing MISP or
  OpenCTI session.
- STIX/TAXII citations are the OASIS Standard HTML editions fetched
  2026-08-25, not drafts.
- MISP Internet-Draft HTML for a “core format” exists on
  misp-standard.org; this ADR does **not** treat that draft as a
  published RFC or Standards Track document. The accepted references
  are the official project and standard landings.
- TAXII poll still performs an outbound HTTP GET of objects the
  operator named; that is document transport, not a live MISP/OpenCTI
  product puller.

## References

Jordan, B., Piazza, R., & Darley, T. (Eds.). (2021, June 10). *STIX
Version 2.1* (OASIS Standard). OASIS Open.
https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html

Jordan, B., & Varner, D. (Eds.). (2021, June 10). *TAXII Version 2.1*
(OASIS Standard). OASIS Open.
https://docs.oasis-open.org/cti/taxii/v2.1/os/taxii-v2.1-os.html

MISP Project. (n.d.). *MISP open source threat intelligence platform
& open standards for threat intelligence sharing*.
https://www.misp-project.org/

MISP Standard. (n.d.). *MISP standard*.
https://www.misp-standard.org/

OpenCTI. (n.d.). *OpenCTI documentation*.
https://docs.opencti.io/latest/
