# Doctoring — in-path Coraza sidecar adapter

This note grounds the issue #86 slice shipped this loop: live `/gateway`
transactions are evaluated by a proven WAF engine through a sidecar adapter.
IEEE PDFs are not redistributed.

## Adopted standards and literature

OWASP Foundation. (n.d.). *OWASP Core Rule Set documentation*.
https://coreruleset.org/docs/

- **Design impact:** CRS remains the detection authority. Wardnet POSTs the
  live method/URI/body to `CORAZA_WAF_URL` and parses the sidecar body with the
  existing Coraza audit adapter. Builtin signatures are a residual scorer, not
  a replacement for CRS.

Coraza. (n.d.). *Coraza Web Application Firewall*.
https://coraza.io/docs/

- **Design impact:** The sidecar contract is Coraza audit JSON (interrupted
  transaction + `messages[]`). A 403 without audit JSON is still treated as an
  interruption. Transport failures do not leak the sidecar URL into SOC
  events. Review-hardening this pass: the evaluate request now carries a
  bounded allowlist of client headers (`host`, `user-agent`, `accept`,
  `content-type`, `referer`, `origin`, `x-requested-with`, `x-forwarded-for`,
  `x-real-ip`, `cookie` — never `Authorization`, capped at 32 headers /
  8 KiB); responses are streamed with a 1 MiB cap; any non-success status
  other than 403 is `Unavailable`; monitor-mode routes and sub-threshold hits
  keep CRS evidence as `engine_hit` events; fail-open outages are recorded.

Scarfone, K., & Mell, P. (2007). *Guide to intrusion detection and prevention
systems (IDPS)* (NIST Special Publication 800-94). National Institute of
Standards and Technology. https://doi.org/NIST.SP.800-94
(Redistributable public-domain PDF:
`docs/papers/nist-sp-800-94-idps-scarfone-mell-2007.pdf`.)

- **Design impact:** IDPS guidance separates detection-path evidence from
  efficacy claims and motivates bounding sensor inputs/outputs: header
  allowlisting, response-size caps, and explicit status handling follow its
  prevention-system hygiene (in-band sensor must fail predictably).

Saltzer, J. H., & Schroeder, M. D. (1975). The protection of information in
computer systems. *Proceedings of the IEEE*, *63*(9), 1278–1308.
https://doi.org/10.1109/PROC.1975.9939

- **Design impact:** Fail-safe defaults. `PROVEN_ENGINE_FAIL_CLOSED` is opt-in
  (`true`/`1`/`yes`/`on`). Production deployments with `CORAZA_WAF_URL` must
  set it so an unreachable engine does not silently allow traffic. Fail-open
  degradations now record `engine_unavailable` events so operators can alert
  on silent protection loss.

Wardnet validates `CORAZA_WAF_URL` before binding. A loopback, private, or
ClusterIP sidecar must be covered by a narrow `destination_allowlist` CIDR in
the credential registry; a hostname-only entry cannot exempt private DNS
answers. Invalid or unavailable sidecar policy now fails startup instead of
silently degrading the first live transaction.

National Institute of Standards and Technology. (2022). *Secure Software
Development Framework (SSDF) version 1.1* (NIST SP 800-218).
https://doi.org/10.6028/NIST.SP.800-218

- **Design impact:** PW.1 / PW.4 — well-secured software and reuse of existing,
  well-secured components. The in-process `coraza` crate needs Go+C at build
  time; a sidecar adapter keeps CI hermetic while still placing CRS in the
  enforcement path.

## Operator next action

Prefer in-process libcoraza: set `CORAZA_LIB_PATH` to the shared library and
`CORAZA_RULES_PATH` (or `CORAZA_DIRECTIVES`) to a pinned OWASP CRS bundle. Point
`CORAZA_WAF_URL` at a Coraza evaluate endpoint only when the process cannot
load the library. Set `PROVEN_ENGINE_FAIL_CLOSED=true` in production. Confirm
`GET /api/waf/engine-status` reports `in_path=true` (`coraza_in_process` or
`coraza_sidecar`) before exposing `/gateway`.
