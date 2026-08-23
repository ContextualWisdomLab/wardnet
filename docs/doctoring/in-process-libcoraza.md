# Doctoring — in-process libcoraza adapter

This note grounds the issue #86 remainder shipped this loop: live `/gateway`
transactions are evaluated by libcoraza inside the Wardnet process. IEEE PDFs
are not redistributed.

## Adopted standards and literature

Coraza. (n.d.). *Coraza Web Application Firewall*.
https://coraza.io/docs/

- **Design impact:** CRS remains the detection authority. Wardnet `dlopen`s
  operator-supplied libcoraza (`CORAZA_LIB_PATH`) and drives the documented C
  ABI (`coraza_new_waf_config`, `coraza_rules_add_file` / `coraza_rules_add`,
  `coraza_process_uri` / headers / body, `coraza_intervention`). Builtin
  signatures stay a residual scorer.

OWASP Foundation. (n.d.). *OWASP Core Rule Set documentation*.
https://coreruleset.org/docs/

- **Design impact:** Rules come from `CORAZA_RULES_PATH` and optional
  `CORAZA_DIRECTIVES`. An empty or missing ruleset fails startup before bind so
  production cannot silently skip CRS.

Saltzer, J. H., & Schroeder, M. D. (1975). The protection of information in
computer systems. *Proceedings of the IEEE*, *63*(9), 1278–1308.
https://doi.org/10.1109/PROC.1975.9939

- **Design impact:** Fail-safe defaults. `PROVEN_ENGINE_FAIL_CLOSED` remains
  opt-in per transaction; a configured library that cannot load is always
  fail-closed at process start. Unset `CORAZA_LIB_PATH` keeps the sidecar path
  (`CORAZA_WAF_URL`) from the previous slice.

National Institute of Standards and Technology. (2022). *Secure Software
Development Framework (SSDF) version 1.1* (NIST SP 800-218).
https://doi.org/10.6028/NIST.SP.800-218

- **Design impact:** PW.1 / PW.4 — reuse a well-secured component. Building
  libcoraza still needs Go+C; CI stays hermetic by compiling a fixture cdylib
  that exports the same symbols. Production points `CORAZA_LIB_PATH` at a real
  libcoraza build.

## Operator next action

Install libcoraza and a pinned OWASP CRS bundle. Set `CORAZA_LIB_PATH` and
`CORAZA_RULES_PATH`. Set `PROVEN_ENGINE_FAIL_CLOSED=true`. Confirm
`GET /api/waf/engine-status` reports `mode=coraza_in_process`,
`in_path=true`, and a non-zero `in_process_rules` before exposing `/gateway`.
The library path is not published on health or engine-status surfaces.
