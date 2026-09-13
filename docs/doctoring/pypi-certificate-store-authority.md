# PyPI certificate-store authority

Status: Proposed implementation evidence on Draft PR #129. This document does not make the branch released or protected truth.

## Problem

Wardnet's Agent Artifact Admission decides whether one structured installer intent may proceed to a downstream executor. An approved PyPI package coordinate, digest, registry and workspace manifest do not authorize the caller to replace the TLS certificate store used to authenticate that registry.

pip 26.2.1 documents HTTPS certificate verification as the default protection against man-in-the-middle attacks and exposes `--cert` / `PIP_CERT` for selecting a certificate bundle. The same pip documentation identifies `REQUESTS_CA_BUNDLE` and `CURL_CA_BUNDLE` as ambient alternatives. A caller-controlled certificate store therefore changes trust authority independently of the reviewed package coordinate.

The direct-pip CLI uses Python `optparse`-compatible long-option parsing. `optparse` resolves an unambiguous long-option prefix and accepts an option argument either as `--option=value` or as a following argv element. On Wardnet's reviewed direct-pip option surface, `--c` is ambiguous while `--ce` and `--cer` uniquely select `--cert`. Exact-string matching of `--cert` alone therefore leaves an accepted trust-authority spelling outside the policy classifier.

## Decision

For structured `pip` and `pip3` argv, Wardnet classifies canonical `--cert` and accepted unambiguous `--ce` / `--cer` abbreviations as `AlternateTrustRoot` and fails the admission request closed. The generic `requests_alternate_trust_root` / `matches_cli_flag` path remains the authority for the canonical exact `--cert` spelling. A narrow `pypi_certificate_store_authority` overlay owns only pip's verified abbreviation grammar that the generic exact-option guard intentionally does not model.

The abbreviation classifier is bounded to direct `pip install` / `pip3 install`, strips an attached `=value` only for option-name comparison, rejects the ambiguous `--c`, excludes the canonical full spelling from its own responsibility, and does not apply pip grammar to `uv`. Both attached and separate-value `--ce` forms are covered by admission-level tests; the separate value may independently be rejected by operand validation, but the trust-authority reason must still be present.

Wardnet does not inspect, clear or enforce `PIP_CERT`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, filesystem certificate contents, operating-system trust stores, or the executor's effective environment. Those are runtime execution/isolation concerns owned by `quarantine-sandbox-runtime`. The corresponding environment-authority witness is tracked in `quarantine-sandbox-runtime#49`. EgressWeave retains outbound transport authorization; Wardnet does not convert an admission receipt into network authority.

An `allow` receipt therefore means only that the exact reviewed structured installer intent passed Wardnet policy. It is not proof that retrieved bytes, TLS peer authentication, effective environment, network egress or execution are safe.

## Alternatives considered

Allowing arbitrary `--cert` values because the package artifact itself is digest-pinned was rejected. Artifact integrity does not make a caller-selected trust anchor benign: registry metadata, authentication and other TLS-protected exchanges can still be redirected or observed, and the reviewed Wardnet policy carries no independently approved certificate-bundle identity.

Adding certificate-file inspection to Wardnet was rejected because it would duplicate runtime filesystem/environment authority and couple the admission bounded context to executor state. A future released contract may carry an immutable, canonical-owner certificate-policy identity, but mutable paths or sibling source are not production authority.

Teaching the global long-option matcher every command-specific abbreviation was rejected. Long-option abbreviation is parser- and option-surface-dependent; applying pip grammar globally would create false authority for `uv`, Cargo, npm-family and OCI commands. The narrow direct-pip overlay preserves the existing exact-match invariant everywhere else.

Silently relying on the existing extra-positional-operand rejection for separate certificate values was rejected because it misclassifies the security property. A stable `AlternateTrustRoot` reason is required for audit evidence and policy interpretation even when another validator also rejects the request.

## RED → causal repair evidence

The original canonical-spelling RED `edaf9bbb76a60bf7bdb56ec16e6661c9c86bf9f4` ran in CI `34431988599`, rust job `102729231075`, on hosted Ubuntu 24.04. Checkout, toolchain setup, `cargo fmt --check` and all preceding workspace tests succeeded. The hostile contract proved that `--cert=/tmp/attacker-ca.pem` returned `Allow`, while separate `--cert /tmp/attacker-ca.pem` was blocked without `AlternateTrustRoot`. The minimum canonical repair `43d5e7a8d70d9f7396451ce01402cbcfa7603025` added the exact `--cert` trust-root flag.

Issue #323 then exposed the remaining parser-language gap. Test-only head `500bf5fd18cf69bb53cc25e7c2568c1037fce267` added an approved direct-pip install carrying `--ce=/tmp/attacker-ca.pem`. CI run `34627238783`, rust job `103355194834`, acquired a hosted Ubuntu 24.04 runner, completed checkout, toolchain and formatting, and failed in the semantic test phase because the exact-option guard did not classify pip's accepted abbreviation as trust authority.

The minimum production sequence adds `pypi_certificate_store_authority` as the direct-pip abbreviation overlay and wires only its positive classification into `admission_decision`: `a8fa9524aa25de38d5bed1f0408c1cfdf9e12321` introduces the bounded parser, `6a24fbb21358a619948ca5fd50fc19ac6ff2621f` applies `AlternateTrustRoot`, and `766158d0a850f0273cf4052b58475e06919ec9f0` adds admission-level separate-value coverage. Exact-head GREEN must be reacquired after this documentation commit; predecessor runs are not merge evidence.

## Security traceability

CWE-295 describes improper certificate validation as a weakness that can permit communication with an attacker-controlled or spoofed peer. Wardnet is not itself a TLS implementation, so CWE-295 is used here as threat traceability rather than as a claim that Wardnet validates certificates. The Wardnet control prevents an approved installer intent from authorizing caller-selected certificate trust that could undermine downstream peer authentication.

NIST SP 800-52 Rev. 2 remains the current final NIST TLS implementation guideline as of 2026-09-12. NIST opened a periodic review of Rev. 2 on 2026-05-07 and stated that it expects a future revision to align with newer TLS 1.3 work; that review does not supersede the published Rev. 2. The document's TLS certificate guidance supports keeping peer-authentication trust configuration explicit and governed rather than accepting unreviewed caller overrides.

NIST SP 800-53 Release 5.2.0, published 2025-08-27, remains relevant defense-in-depth traceability for software integrity and controlled system behavior. It does not define pip parsing semantics; the pip/`optparse` primary sources remain authoritative for the exact hostile argv language.

## References

MITRE. (2026). *CWE-295: Improper certificate validation* (CWE Version 4.20). https://cwe.mitre.org/data/definitions/295.html

National Institute of Standards and Technology. (2019). *Guidelines for the selection, configuration, and use of Transport Layer Security (TLS) implementations* (NIST Special Publication 800-52 Rev. 2). https://doi.org/10.6028/NIST.SP.800-52r2

National Institute of Standards and Technology. (2025, August 27). *NIST releases revision to SP 800-53 controls*. https://csrc.nist.gov/News/2025/nist-releases-revision-to-sp-800-53-controls

National Institute of Standards and Technology. (2026, May 7). *NIST requests public comments on SP 800-52 Rev. 2: Guidelines for the selection, configuration, and use of Transport Layer Security (TLS) implementations*. https://www.nist.gov/news-events/news/2026/05/nist-requests-public-comments-sp-800-52-rev-2-guidelines-selection

Python Packaging Authority. (2026). *HTTPS certificates*. pip 26.2.1 documentation. https://pip.pypa.io/en/stable/topics/https-certificates/

Python Software Foundation. (2026). *optparse — Parser for command line options*. Python 3.14.6 documentation. https://docs.python.org/3.14/library/optparse.html
