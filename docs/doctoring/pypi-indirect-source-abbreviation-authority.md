# Direct pip indirect-source abbreviation authority

## Problem and ownership boundary

Wardnet Agent Artifact Admission authorizes only reviewed package coordinates and emits security evidence before an executor runs. It does not read requirements files, clone VCS repositories, fetch packages, authorize outbound transport, install packages, or execute hostile artifacts. Those runtime, transport, analysis, and isolation responsibilities remain with their canonical CWL owners.

The direct `pip`/`pip3` command grammar is security-relevant because a requirements file or editable path/VCS URL can introduce package sources beyond the exact artifact coordinate approved by Wardnet. pip documents `-r, --requirement <file>` as installing from a requirements file and `-e, --editable <path/url>` as installing an editable local or VCS project. Python `optparse` also permits abbreviated long options; its callback contract explicitly notes that an abbreviated spelling such as `--foo` can resolve to canonical `--foobar`.

The preceding Wardnet policy rejected the canonical and short spellings but did not classify the accepted direct-pip long prefixes. Executable parser verification established `--requirem=attacker-requirements.txt` and `--ed=git+https://attacker.invalid/example.git` as accepted selectors, while shorter `--requ` and `--e` remain ambiguous and must not be guessed as valid aliases.

## Exact RED evidence

Test-only commit `ba70e7856abaf45351a6316935130c3a45cb10df` was based on the already-GREEN #325 source and added only `pypi_indirect_source_abbreviation_contract.rs`. Hosted CI `34631567774`, job `103369376385`, acquired `ubuntu-24.04`, checked out that exact head, installed the Rust toolchain, and passed formatting before `cargo test --locked --workspace` failed. The hostile contract requires both accepted prefix forms to fail closed with `ArtifactNotApproved` for direct `pip` and `pip3` even when the explicitly declared package operand itself exactly matches policy.

## Decision

Extend the existing artifact-source-identity boundary rather than adding installer execution or transport behavior. For direct `pip`/`pip3` installs only:

- classify `--requirement` prefixes beginning at the shortest verified unambiguous `--requirem` through the character before the canonical spelling;
- classify `--editable` prefixes beginning at the shortest verified unambiguous `--ed` through the character before the canonical spelling;
- leave canonical `--requirement`, `--editable`, `-r`, and `-e` under the existing policy evaluator;
- leave ambiguous shorter spellings such as `--requ` and `--e` unclassified because the executable parser rejects them;
- do not transfer pip-specific abbreviation grammar to `uv` or another package manager.

This is an admission/source-identity repair. It does not duplicate EgressWeave transport authorization, quarantine execution/isolation, AppGuardrail analysis, or contextual-orchestrator agent orchestration.

## Alternatives rejected

Blocking every option prefix that begins with `--r` or `--e` was rejected because that would invent parser semantics and create false positives for ambiguous or unrelated pip options. Treating requirements/editable material as implicitly approved by the explicit package coordinate was rejected because pip can expand those selectors into additional or differently sourced functionality. Fetching and validating the referenced file or repository inside Wardnet was rejected because it would cross the pre-execution policy boundary and duplicate runtime/source acquisition owners.

## Security effect and residual risk

The repair closes a caller-intent bypass in which an approved explicit package operand could coexist with an undeclared requirements file or editable VCS/local source. This is consistent with CWE-829's concern about importing functionality from outside the intended control sphere and with SSDF's emphasis on preventing recurrence through verified security requirements and tests.

Residual risk remains whenever pip changes its parser or adds source-expanding selectors. Wardnet should add a hostile RED contract before expanding its parser-sensitive admission grammar; it must not infer aliases solely from option names.

## Traceability

- NIST SP 800-218, SSDF v1.1 remains the final normative SSDF publication; SP 800-218 Rev. 1 / SSDF v1.2 is an Initial Public Draft as of this decision and is informative only.
- PyPA pip install documentation defines requirements-file and editable-source installation as distinct source-expanding input forms.
- Python `optparse` documentation explicitly recognizes abbreviated long options.
- CWE-829 describes inclusion of executable functionality from a source outside the intended control sphere and recommends strict known-good input validation.

## References (APA 7th)

MITRE. (2026). *CWE-829: Inclusion of functionality from untrusted control sphere* (Version 4.20). Common Weakness Enumeration. https://cwe.mitre.org/data/definitions/829.html

National Institute of Standards and Technology. (2022). *Secure software development framework (SSDF) version 1.1: Recommendations for mitigating the risk of software vulnerabilities* (NIST Special Publication 800-218). https://doi.org/10.6028/NIST.SP.800-218

National Institute of Standards and Technology. (2025). *Secure software development framework (SSDF) version 1.2: Recommendations for mitigating the risk of software vulnerabilities* (NIST Special Publication 800-218 Rev. 1, Initial Public Draft). https://csrc.nist.gov/pubs/sp/800/218/r1/ipd

Python Packaging Authority. (n.d.). *pip install — pip documentation v26.2.1*. Retrieved September 12, 2026, from https://pip.pypa.io/en/stable/cli/pip_install/

Python Software Foundation. (n.d.). *optparse — Parser for command line options*. Retrieved September 12, 2026, from https://docs.python.org/3/library/optparse.html
