# Doctoring — CI attack-evidence battery (issue #11)

This note grounds the issue #11 slice: the compiled gateway binary is started
in CI with a hermetic libcoraza engine, a deterministic OWASP CRS attack
battery is fired over real HTTP, and every attempt must be blocked with the
cited CRS rule id and recorded as a security event that keeps the forwarded
client IP unmasked.

## What is proven (and what is not)

Proven end to end on the real binary: operator-supplied `CORAZA_LIB_PATH`
loading, rules-file admission, per-transaction evaluation of method/URI/body,
block responses citing `coraza/crs: rule <id>`, benign traffic still
forwarding, and unmasked client attribution in `/api/events`.

Not proven: detection *quality* against arbitrary live traffic. The CI engine
is the build-script ABI stub (`src/coraza_abi_stub.rs`), a fixture that
mirrors the libcoraza C ABI, not Coraza itself. Quality evidence stays with an
operator deployment using a real libcoraza plus the OWASP Core Rule Set; this
slice only removes "the path was never exercised in CI" from the gap list.

## Adopted standards and literature

OWASP Foundation. (n.d.). *OWASP Core Rule Set documentation*.
https://coreruleset.org/docs/

- **Design impact:** Battery entries map to canonical CRS rule families —
  942100 SQLi (libinjection), 941100 XSS (libinjection), 930100 path
  traversal, 932100 Unix command injection, 944120 Log4j JNDI. Rule ids in
  block reasons and events stay CRS ids so operator dashboards read the same
  vocabulary in CI evidence and production.

Scarfone, K., & Mell, P. (2007). *Guide to intrusion detection and prevention
systems (IDPS)* (NIST Special Publication 800-94). National Institute of
Standards and Technology. https://doi.org/NIST.SP.800-94

- **Design impact:** IDPS evaluation distinguishes the detection *path* from
  detection *efficacy*. SP 800-94's testing guidance motivates keeping the two
  claims separate: CI asserts the prevention path (signature → interrupt →
  block → record), while efficacy against evasive payloads requires curated
  corpora and is explicitly out of scope for this fixture.

Saltzer, J. H., & Schroeder, M. D. (1975). The protection of information in
computer systems. *Proceedings of the IEEE*, *63*(9), 1278–1308.
https://doi.org/10.1109/PROC.1975.9939

- **Design impact:** Complete mediation and fail-safe defaults. The battery
  runs through the same route pipeline (`mode: block`) as production traffic,
  so no test-only bypass exists; an engine that fails to load refuses startup
  before bind instead of degrading silently.

MITRE. (n.d.). *CWE-20: Improper input validation*. MITRE Corporation.
https://cwe.mitre.org/data/definitions/20.html

- **Design impact:** The battery covers encoded variants (`%3Cscript`,
  `%24%7BJNDI`, `..%2F`) because input-validation defects classically live at
  decoding boundaries; the gateway evaluates the raw request line exactly as
  received, so fixtures pin that behavior rather than a decoded copy.

## Verification posture

- `tests/binary.rs::live_gateway_detects_owasp_attack_battery_end_to_end`
  spawns the binary, creates the block route over the admin API, fires nine
  battery cases (GET query attacks across five rule families plus a POST-body
  XSS), asserts HTTP 403 + `engine=coraza` + cited rule id per case, asserts a
  benign request forwards, and asserts `/api/events` records one event per
  attempt with `X-Forwarded-For` preserved verbatim.
- `src/coraza_inprocess.rs::stub_engine_battery_matches_each_owasp_family`
  pins the fixture contract itself, including first-match ordering so the
  overlapping `; cat /etc/passwd` payload attributes to RCE (932100), not
  traversal.
