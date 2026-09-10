# PyPI certificate-store authority

Status: Proposed implementation evidence on Draft PR #129. This document does not make the branch released or protected truth.

## Problem

Wardnet's Agent Artifact Admission decides whether one structured installer intent may proceed to a downstream executor. An approved PyPI package coordinate, digest, registry and workspace manifest do not authorize the caller to replace the TLS certificate store used to authenticate that registry.

pip 26.2.1 documents HTTPS certificate verification as the default protection against man-in-the-middle attacks and exposes `--cert` / `PIP_CERT` for selecting a certificate bundle. The same pip documentation identifies `REQUESTS_CA_BUNDLE` and `CURL_CA_BUNDLE` as ambient alternatives. A caller-controlled certificate store therefore changes trust authority independently of the reviewed package coordinate.

## Decision

For structured `pip` and `pip3` argv, Wardnet classifies `--cert` as `AlternateTrustRoot` and fails the admission request closed. The existing `requests_alternate_trust_root` classifier and `matches_cli_flag` parser remain the sole Wardnet authority for this argv property; both `--cert=<path>` and separate `--cert <path>` spellings are covered without a parallel classifier.

Wardnet does not inspect, clear or enforce `PIP_CERT`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, filesystem certificate contents, operating-system trust stores, or the executor's effective environment. Those are runtime execution/isolation concerns owned by `quarantine-sandbox-runtime`. The corresponding environment-authority witness is tracked in `quarantine-sandbox-runtime#49`. EgressWeave retains outbound transport authorization; Wardnet does not convert an admission receipt into network authority.

An `allow` receipt therefore means only that the exact reviewed structured installer intent passed Wardnet policy. It is not proof that retrieved bytes, TLS peer authentication, effective environment, network egress or execution are safe.

## Alternatives considered

Allowing arbitrary `--cert` values because the package artifact itself is digest-pinned was rejected. Artifact integrity does not make a caller-selected trust anchor benign: registry metadata, authentication and other TLS-protected exchanges can still be redirected or observed, and the reviewed Wardnet policy carries no independently approved certificate-bundle identity.

Adding certificate-file inspection to Wardnet was rejected because it would duplicate runtime filesystem/environment authority and couple the admission bounded context to executor state. A future released contract may carry an immutable, canonical-owner certificate-policy identity, but mutable paths or sibling source are not production authority.

Silently relying on the existing extra-positional-operand rejection for separate `--cert <path>` was rejected because it misclassifies the security property. A stable `AlternateTrustRoot` reason is required for audit evidence and policy interpretation.

## RED → causal repair evidence

Test-only exact `edaf9bbb76a60bf7bdb56ec16e6661c9c86bf9f4` ran in CI `34431988599`, rust job `102729231075`, on hosted Ubuntu 24.04. Checkout, toolchain setup, `cargo fmt --check` and all preceding workspace tests succeeded. The hostile contract then proved both relevant failures:

- `pip install cwl-example==1.2.3 --require-hashes --no-deps --cert=/tmp/attacker-ca.pem` returned `Allow` instead of `Block`.
- `pip install ... --cert /tmp/attacker-ca.pem` was blocked only as `ArtifactNotApproved` and lacked `AlternateTrustRoot`.

The positive control without certificate override and the duplicate-reason control passed. The minimum production successor `43d5e7a8d70d9f7396451ce01402cbcfa7603025` adds exactly one `--cert` entry to the existing forbidden trust-root flag list; comparison from the RED head is one file, one added line. Exact-head GREEN must be reacquired after this documentation commit before the candidate may be promoted.

## Security traceability

CWE-295 describes improper certificate validation as a weakness that can permit communication with an attacker-controlled or spoofed peer. Wardnet is not itself a TLS implementation, so CWE-295 is used here as threat traceability rather than as a claim that Wardnet validates certificates. The Wardnet control prevents an approved installer intent from authorizing caller-selected certificate trust that could undermine downstream peer authentication.

NIST SP 800-52 Rev. 2 remains the current final NIST TLS implementation guideline as of 2026-09-10. NIST opened a periodic review of Rev. 2 on 2026-05-07 and stated that it expects a future revision to align with newer TLS 1.3 work; that review does not supersede the published Rev. 2. The document's TLS certificate guidance supports keeping peer-authentication trust configuration explicit and governed rather than accepting unreviewed caller overrides.

## References

MITRE. (2026). *CWE-295: Improper certificate validation* (CWE Version 4.20). https://cwe.mitre.org/data/definitions/295.html

National Institute of Standards and Technology. (2019). *Guidelines for the selection, configuration, and use of Transport Layer Security (TLS) implementations* (NIST Special Publication 800-52 Rev. 2). https://doi.org/10.6028/NIST.SP.800-52r2

National Institute of Standards and Technology. (2026, May 7). *NIST requests public comments on SP 800-52 Rev. 2: Guidelines for the selection, configuration, and use of Transport Layer Security (TLS) implementations*. https://www.nist.gov/news-events/news/2026/05/nist-requests-public-comments-sp-800-52-rev-2-guidelines-selection

Python Packaging Authority. (2026). *HTTPS certificates*. pip 26.2.1 documentation. https://pip.pypa.io/en/stable/topics/https-certificates/
