# Direct pip dependency-group abbreviation authority

## Problem and ownership boundary

Wardnet Agent Artifact Admission decides whether a structured installer intent stays inside reviewed artifact authority and emits the corresponding pre-execution security evidence. It does not parse project manifests to resolve dependency-group members, fetch packages, perform network/TLS operations, install or execute artifacts, isolate hostile workloads, or discover runtime credentials. Those responsibilities remain with their canonical CWL owners.

Direct pip supports `--group <[path:]group>` to install a dependency group from `pyproject.toml`. The existing Wardnet guard rejected canonical `--group` but not the shorter unambiguous spelling accepted by pip's Python `optparse`-compatible long-option grammar. Executable parser verification against pip 25.1.1 established `--gro` as accepted for `--group`; shorter `--g` and `--gr` are ambiguous on the pinned option surface and must not be invented as aliases.

## Hostile realistic RED

Test-only head `00f06e21e56f8a85c38996c0927480fa4c87b0de` was branched from exact Agent Artifact Admission parent `6df3a4a673e9d966c5c6bac760044fc85aaf926a` and changed only `crates/agent-artifact-admission/tests/pip_dependency_group_abbreviation_contract.rs`.

Hosted CI run `34634809930`, Rust job `103380003463`, acquired GitHub-hosted Ubuntu 24.04, checked out the pull-request candidate merge built from that unchanged parent and test-only head, installed Rust 1.98.1, and passed `cargo fmt --check`. `cargo test --locked --workspace` then reached the hostile contract and failed because direct `pip install ... --gro=attacker-group` returned `Allow` rather than `Block`. The failure therefore exercises Wardnet admission semantics rather than runner, checkout, toolchain, formatting, or unrelated workspace behavior.

## Decision

Classify only the pinned direct-pip dependency-group option language already represented by the canonical authority boundary:

- `--gro` and `--gro=<value>`;
- `--grou` and `--grou=<value>`;
- canonical `--group` and `--group=<value>`.

The matcher is bounded by the shortest verified unambiguous prefix `--gro` and the canonical option `--group`. Ambiguous `--g`/`--gr`, superstrings such as `--groups`, and unrelated options remain outside this authority classifier. Separate-value use is classified by the selector token itself; attached-value use is classified after splitting only the first `=`.

This repair does not implement pip's dependency resolution or inspect dependency-group contents. A caller-selected group remains unapproved artifact authority and fails closed before execution. uv and other installers retain independent grammars.

## Alternatives rejected

Treating every `--g...` token as `--group` was rejected because it would invent parser behavior and cause false positives for ambiguous or unrelated options. Leaving abbreviated selectors to generic unknown-operand handling was rejected because the selector itself is security-significant authority: attached `--gro=<group>` contains no separate operand for another guard to catch and was demonstrably allowed. Reimplementing pip project/dependency resolution in Wardnet was rejected because that would cross the admission bounded context into package-manager execution and artifact-analysis ownership.

## Security effect and residual risk

The repair closes a structured-argv admission bypass in which an otherwise approved direct pip/pip3 install could import dependency-group members that were never represented by the reviewed artifact set. The bounded unit contract also prevents future prefix widening without parser evidence.

Residual risk remains if pip changes its option set or parser behavior. Any newly accepted abbreviation or new dependency-import selector requires fresh executable parser verification and a hostile Wardnet RED; spelling similarity alone is not authority.

## Traceability

NIST SP 800-218 SSDF v1.1 remains the final normative SSDF publication used here. NIST SP 800-218 Rev. 1 / SSDF v1.2 is an Initial Public Draft published December 17, 2025 and is informative only. PyPA pip documentation is the primary product authority for `pip install --group`; Python `optparse` documentation is the primary parser authority for unambiguous long-option abbreviations. CWE-20 supports bounded validation of untrusted structured input, while CWE-829 is relevant when caller-controlled dependency inclusion crosses the reviewed artifact authority boundary.

## References (APA 7th)

MITRE. (2026). *CWE-20: Improper input validation* (Version 4.20). Common Weakness Enumeration. https://cwe.mitre.org/data/definitions/20.html

MITRE. (2026). *CWE-829: Inclusion of functionality from untrusted control sphere* (Version 4.20). Common Weakness Enumeration. https://cwe.mitre.org/data/definitions/829.html

National Institute of Standards and Technology. (2022). *Secure software development framework (SSDF) version 1.1: Recommendations for mitigating the risk of software vulnerabilities* (NIST Special Publication 800-218). https://doi.org/10.6028/NIST.SP.800-218

National Institute of Standards and Technology. (2025). *Secure software development framework (SSDF) version 1.2: Recommendations for mitigating the risk of software vulnerabilities* (NIST Special Publication 800-218 Rev. 1, Initial Public Draft). https://doi.org/10.6028/NIST.SP.800-218r1.ipd

Python Packaging Authority. (n.d.). *pip install — pip documentation*. Retrieved September 12, 2026, from https://pip.pypa.io/en/latest/cli/pip_install/

Python Software Foundation. (n.d.). *optparse — Parser for command line options*. Retrieved September 12, 2026, from https://docs.python.org/3/library/optparse.html
