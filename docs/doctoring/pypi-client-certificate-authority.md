# PyPI client-certificate authority

Status: Draft until the exact implementation head is merged into the Agent Artifact Admission aggregate and that aggregate reaches protected `main`.

## Problem

Wardnet approves package artifacts and reviewed registries; that approval must not implicitly authorize a caller-selected TLS client identity. Direct `pip install` can select a PEM containing a client certificate and private key with `--client-cert`. At the pinned pip parser baseline, long options are parsed through Python `optparse` semantics, which accept an unambiguous prefix. Therefore checking only the canonical spelling leaves parser-equivalent forms such as `--cl=/tmp/client.pem` outside explicit trust-authority evidence.

This is a structured-command admission concern owned by Wardnet. Wardnet does not load the certificate, resolve credentials, initiate TLS, or take over Keyverse, EgressWeave, quarantine-sandbox-runtime, contextual-orchestrator, or AppGuardrail responsibilities.

## Constraint and decision

The direct-pip classifier recognizes only the parser language demonstrated by the pinned upstream surface:

- executable is `pip` or `pip3`;
- command is `install`;
- the option name is the canonical `--client-cert` spelling or a prefix of that spelling no shorter than `--cl`;
- attached (`--cl=/path`) and separate-value (`--cl /path`) forms are classified;
- shorter ambiguous forms such as `--c` and unrelated lookalikes are not promoted to this authority.

The classification adds `alternate_trust_root` and blocks admission. The certificate remains opaque data; no file access or TLS behavior is introduced.

The rejected alternative was a repository-wide `starts_with("--cl")` rule. It would both over-classify unrelated arguments and copy pip parser semantics into package managers that do not share them. Another rejected alternative was exact matching of `--client-cert`, because it does not represent the command parser that will consume the admitted argv.

## RED/GREEN evidence

Issue `#321` records the hostile case and acceptance criteria. Draft child PR `#322` was created from exact Agent Artifact Admission head `1fb88b134123bea9b883374fba37b54345b1168c`.

RED commit `d05f8acd412835d3ebd1284759cf888f3b2b4e4a` left production source byte-identical. Hosted CI run `34625892042`, job `103350772594`, passed checkout, toolchain and formatting, then failed the semantic assertion because `--cl=/tmp/attacker-client.pem` produced `MissingSafetyFlag` without `AlternateTrustRoot`. That failure demonstrates the missing authority classification rather than runner or formatting noise.

GREEN requires the same hostile case plus separate-value prefix coverage to return `Block` with `AlternateTrustRoot`, followed by exact-head formatting, locked workspace tests, strict Clippy and then-live security/fuzz evidence before ordinary non-force integration into the still-current aggregate.

## Traceability

Python Packaging Authority. (2026). *pip command options* (commit `2b28a816d043826f2ba10ff1d22ec3d94d2ed7c5`). `src/pip/_internal/cli/cmdoptions.py` defines `--client-cert` as the path to a PEM-encoded client certificate and private key; `src/pip/_internal/commands/install.py` imports and composes that shared option surface. https://github.com/pypa/pip/tree/2b28a816d043826f2ba10ff1d22ec3d94d2ed7c5

Python Software Foundation. (2026). *getopt — C-style parser for command line options*. Python 3.14 documentation states that long options may be recognized by a prefix when it matches exactly one accepted option. https://docs.python.org/3.14/library/getopt.html

Joint Task Force. (2025). *Security and Privacy Controls for Information Systems and Organizations* (NIST SP 800-53 Rev. 5, Release 5.2.0). National Institute of Standards and Technology. The boundary supports least privilege and authenticator-management intent by preventing artifact approval from conferring an unreviewed client credential authority. https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final

MITRE. (2025). *CWE-15: External Control of System or Configuration Setting*. https://cwe.mitre.org/data/definitions/15.html
